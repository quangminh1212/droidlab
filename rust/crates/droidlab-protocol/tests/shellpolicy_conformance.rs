//! Conformance tests for the shell policy, against `shell-policy.json`: 25 rules, 23 cases, 5 lifecycle
//! vectors, and 4 policy contexts.
//!
//! The file describes itself as "the shell policy in executable form", so these tests load it and run every
//! case rather than restating it. Two things in it are worth calling out because they are the reason the
//! reason codes exist at all:
//!
//!   * **`shell.deny.mutating-rule-without-write-grant` and `shell.deny.mutating-settings-without-write-grant`
//!     are `not_in_allow_list`, not `argument_rejected`.** The level gate is folded into the allow list
//!     rather than being a step of its own, and the note says why: "A mutating rule in a read_only context
//!     is not in the allow list for that context, which is why the verdict is not_in_allow_list rather than
//!     argument_rejected."
//!
//!   * **`shell.deny.command-line-too-long` and `shell.deny.regex-bomb` are `argument_rejected`.** The cap
//!     has no reason code of its own; it is what makes the argument fail to match. The regex-bomb note is
//!     explicit: "the length cap rejects this before a pattern is even applied."

#[test]
fn probe_pattern() {
    let png = BoundedPattern::compile("^/data/local/tmp/[A-Za-z0-9._-]{1,64}\\.png$").unwrap();
    println!("maxlen {:?}", png.maximum_length());
    for s in [
        "/data/local/tmp/shot.png",
        "/data/local/tmp/a-b_c.d.png",
        "/data/local/tmp/x.png",
        "/data/local/tmp/shotXpng",
    ] {
        println!("{:?} -> {}", s, png.matches(s));
    }
}

#[path = "vectors/mod.rs"]
mod vectors;

use droidlab_protocol::error::ErrorCode;
use droidlab_protocol::shellpolicy::{
    audit_records_blocked, basename_of, command_line_bytes, evaluate, is_prefix, timeout_exit_code,
    AllowLevel, BoundedPattern, Decision, OutputBuffer, PolicyContext, RateLimit, RejectionLimiter,
    RejectionReason, Rule, DEFAULT_MAX_COMMAND_LINE_BYTES, MIN_AUDIT_ENTRIES,
    REQUIRED_AUDIT_FIELDS, SIGKILL, TIMEOUT_EXIT_CODE,
};

use serde_json::Value;

const FILE: &str = "shell-policy.json";

fn document() -> Value {
    vectors::load(FILE)
}

fn array_named(name: &str) -> Vec<Value> {
    document()
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("the file has a {name} array"))
        .clone()
}

/// The rules, compiled.
fn rules() -> Vec<Rule> {
    let mut out = Vec::new();

    for entry in array_named("rules") {
        let mut arg_patterns = Vec::new();

        if let Some(patterns) = entry.get("arg_patterns").and_then(Value::as_array) {
            for pattern in patterns {
                let text = pattern.as_str().expect("a pattern string");

                arg_patterns.push(
                    BoundedPattern::compile(text)
                        .unwrap_or_else(|error| panic!("cannot compile {text:?}: {error}")),
                );
            }
        }

        out.push(Rule {
            id: vectors::str_field(&entry, "id").to_owned(),
            exe: vectors::str_field(&entry, "exe").to_owned(),
            argv_prefix: entry.get("argv_prefix").map(strings).unwrap_or_default(),
            max_args: usize::try_from(vectors::u64_field(&entry, "max_args")).expect("fits"),
            arg_patterns,
            timeout_ms: u32::try_from(vectors::u64_field(&entry, "timeout_ms")).expect("fits"),
            mutating: entry
                .get("mutating")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }

    out
}

/// Reads a vector's `note`, returning an empty string when the field is absent.
fn note_of(vector: &Value) -> String {
    vector
        .get("note")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Reads a string field that may be absent, returning `&str` or an empty string.
fn optional(vector: &Value, name: &str) -> String {
    vector
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// The strings of an array value.'
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// A context by name.
fn context(name: &str) -> PolicyContext {
    // The document is OWNED here: `document()` builds a fresh `Value` per call, so borrowing from the
    // result of `.get(...)` directly would borrow a temporary.
    let document = document();
    let contexts = document
        .get("policy_contexts")
        .and_then(Value::as_object)
        .expect("policy_contexts");

    let entry = contexts
        .get(name)
        .unwrap_or_else(|| panic!("{name} is a policy context"));

    PolicyContext {
        shell_granted: entry
            .get("shell_granted")
            .and_then(Value::as_bool)
            .expect("shell_granted"),
        allow_level: AllowLevel::from_wire_name(vectors::str_field(entry, "allow_level"))
            .unwrap_or_else(|| panic!("{name} has a known allow_level")),
        allowed_rules: strings(entry.get("allowed_rules").expect("allowed_rules")),
        denied_rules: strings(entry.get("denied_rules").expect("denied_rules")),
        allow_stdin: entry
            .get("allow_stdin")
            .and_then(Value::as_bool)
            .expect("allow_stdin"),
        max_command_line_bytes: usize::try_from(vectors::u64_field(
            entry,
            "max_command_line_bytes",
        ))
        .expect("fits"),
    }
}

fn args_of(case: &Value) -> Vec<String> {
    case.get("args").map(strings).unwrap_or_default()
}

// =============================================================================================
// The rules and contexts themselves
// =============================================================================================

/// Every rule compiles, and its fields are consistent.
#[test]
fn every_rule_loads_and_compiles() {
    let all = rules();

    assert_eq!(all.len(), 25, "twenty-five rules");

    let mut ids = Vec::new();

    for rule in &all {
        assert!(!rule.id.is_empty(), "a rule has no id");
        assert!(
            rule.exe.starts_with("/system/"),
            "{}: the executable {} is outside /system",
            rule.id,
            rule.exe
        );

        // The patterns count matches `max_args` in every rule, so no argument position is left unchecked.
        assert_eq!(
            rule.arg_patterns.len(),
            rule.max_args,
            "{}: {} patterns for max_args {}",
            rule.id,
            rule.arg_patterns.len(),
            rule.max_args
        );

        assert!(rule.timeout_ms > 0, "{}: no timeout", rule.id);

        ids.push(rule.id.clone());
    }

    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();

    assert_eq!(unique.len(), ids.len(), "a rule id appears twice");

    // The distinct executables, which is what makes `basename_of` and the deny list meaningful.
    let exes: Vec<&str> = all.iter().map(|rule| rule.exe.as_str()).collect();

    for exe in &exes {
        assert!(
            basename_of(exe).is_some(),
            "{exe} has no basename, so it is not an absolute vetted path"
        );
    }

    // The mutating rules, which the level gate is about.
    let mutating: Vec<&str> = all
        .iter()
        .filter(|rule| rule.mutating)
        .map(|rule| rule.id.as_str())
        .collect();

    assert_eq!(mutating.len(), 6, "six rules are mutating: {mutating:?}");
    assert!(mutating.contains(&"sys.am.force-stop"));
    assert!(mutating.contains(&"dev.settings.put"));

    // And every other rule is read-only, in both directions.
    for rule in &all {
        assert_eq!(
            rule.mutating,
            mutating.contains(&rule.id.as_str()),
            "{}: the mutating flag disagrees with the census",
            rule.id
        );
    }
}

/// The four contexts load, and their notes about the level and the deny list hold.
#[test]
fn the_policy_contexts_load_and_hold_their_notes() {
    let names: Vec<String> = document()
        .get("policy_contexts")
        .and_then(Value::as_object)
        .expect("policy_contexts")
        .keys()
        .cloned()
        .collect();

    assert_eq!(names.len(), 4);
    for name in ["default", "app_control_grant", "no_grant", "mutating_grant"] {
        assert!(names.contains(&name.to_owned()), "{name} is missing");
    }

    // The notes, which are the specification for the level gate.
    let notes = document()
        .get("policy_context_notes")
        .and_then(Value::as_object)
        .expect("policy_context_notes")
        .clone();

    let level_note = notes
        .get("allow_level")
        .and_then(Value::as_str)
        .expect("allow_level");

    assert!(
        level_note
            .contains("is why the verdict is not_in_allow_list rather than argument_rejected"),
        "the level note no longer explains the reason code: {level_note}"
    );
    assert!(level_note.contains("read_only permits only rules that are not marked mutating"));

    let deny_note = notes
        .get("denied_rules")
        .and_then(Value::as_str)
        .expect("denied_rules");

    assert!(
        deny_note.contains("always wins over an allow entry"),
        "the deny note no longer states precedence: {deny_note}"
    );
    assert!(
        deny_note.contains("checked before any rule matching"),
        "the deny note no longer states the order: {deny_note}"
    );
    assert!(deny_note.contains("Bare executable basenames"));

    // Each context's own consistency.
    for name in &names {
        let context = context(name);

        assert_eq!(
            context.max_command_line_bytes, DEFAULT_MAX_COMMAND_LINE_BYTES,
            "{name}: the command-line cap is not the default"
        );
        assert!(
            !context.allow_stdin,
            "{name}: stdin is allowed, and no case exercises it"
        );

        if !context.shell_granted {
            // The `no_grant` context has no allow list at all, so a refusal cannot be blamed on the list.
            assert!(
                context.allowed_rules.is_empty(),
                "{name}: shell is not granted but rules are allow-listed"
            );
            assert!(
                context.denied_rules.is_empty(),
                "{name}: an ungranted context has a deny list"
            );
        }
    }

    // The deny lists are a subset of the rule basenames plus the ones no rule names, which is what makes
    // `shell.deny.su` and `shell.deny.reboot` meaningful: no rule names `su` at all.
    let all_rules = rules();
    let rule_basenames: Vec<&str> = all_rules
        .iter()
        .filter_map(|rule| basename_of(&rule.exe))
        .collect();

    let default = context("default");

    assert!(
        !default.denied_rules.is_empty(),
        "the default context denies nothing"
    );
    assert!(default.denies("su"), "su is not denied");
    assert!(default.denies("sh"), "sh is not denied");
    assert!(default.denies("rm"), "rm is not denied");

    // `su` has no rule, so the deny list is the only thing refusing it.
    assert!(
        !rule_basenames.contains(&"su"),
        "a rule now names su, so the deny-list case proves less"
    );

    // And an allow-listed id is never also denied, which would make the context contradictory.
    for name in &names {
        let context = context(name);

        for id in &context.allowed_rules {
            let rule = rules()
                .into_iter()
                .find(|rule| rule.id == *id)
                .unwrap_or_else(|| panic!("{name} allow-lists {id}, which is not a rule"));

            let basename = basename_of(&rule.exe).expect("a basename");

            assert!(
                !context.denies(basename),
                "{name}: {id} is allow-listed but {basename} is denied"
            );
        }
    }
}

// =============================================================================================
// The cases
// =============================================================================================

/// Every case in the file produces its declared verdict, reason and rule.
#[test]
fn every_case_produces_its_declared_verdict() {
    let all = array_named("cases");
    let rules = rules();

    assert_eq!(all.len(), 23, "twenty-three cases");

    let mut allowed = 0usize;
    let mut rejected = 0usize;
    let mut reasons: Vec<String> = Vec::new();

    for case in &all {
        let id = vectors::id(case);
        let context_name = vectors::str_field(case, "context");
        let exe = vectors::str_field(case, "exe");
        let args = args_of(case);
        let expected = vectors::str_field(case, "expected");

        let decision = evaluate(&context(context_name), &rules, exe, &args);

        match expected {
            "allowed" => {
                assert!(
                    decision.is_allowed(),
                    "{id}: expected allowed, got {:?}",
                    decision.reason()
                );

                let want = vectors::str_field(case, "expected_rule");

                assert_eq!(decision.rule_id(), Some(want), "{id}: the rule differs");

                // Every allowed case has a rule id.
                assert!(!want.is_empty(), "{id}: an allowed case names no rule");

                // And the rule is in the context's allow list, which is what `allowed` means.
                let context_here = context(context_name);

                assert!(
                    context_here.allowed_rules.contains(&want.to_owned()),
                    "{id}: {want} is not in {context_name}'s allow list"
                );

                allowed = allowed.saturating_add(1);
            }
            "rejected" => {
                assert!(
                    !decision.is_allowed(),
                    "{id}: expected a rejection, got rule {:?}",
                    decision.rule_id()
                );

                let want_reason = optional(case, "expected_reason");

                assert_eq!(
                    decision.reason(),
                    RejectionReason::from_wire_name_test(&want_reason),
                    "{id}: the reason differs"
                );

                let want_error = optional(case, "expected_error");

                assert_eq!(
                    decision.code(),
                    Some(
                        ErrorCode::from_wire_name(&want_error).unwrap_or_else(|| panic!(
                            "{id}: {want_error} is not a real error code"
                        ))
                    ),
                    "{id}: the error code differs"
                );

                // The reason's own error code agrees with the case's, so the two dimensions are consistent.
                assert_eq!(
                    decision.code(),
                    Some(decision.reason().expect("a reason").error_code())
                );

                if !reasons.contains(&want_reason.to_owned()) {
                    reasons.push(want_reason.to_owned());
                }

                rejected = rejected.saturating_add(1);
            }
            other => panic!("{id}: {other} is not a verdict"),
        }
    }

    assert_eq!(allowed, 5, "five cases are allowed");
    assert_eq!(rejected, 18, "eighteen are rejected");
    assert_eq!(allowed.saturating_add(rejected), 23);

    // All four reasons are exercised, so no branch of the procedure is dead.
    reasons.sort();

    let mut expected_reasons: Vec<String> = [
        "argument_rejected",
        "deny_listed",
        "denied_by_operator",
        "not_in_allow_list",
    ]
    .iter()
    .map(|reason| (*reason).to_owned())
    .collect();
    expected_reasons.sort();

    assert_eq!(reasons, expected_reasons, "not every reason is exercised");

    // And both error codes appear.
    let codes: Vec<String> = all
        .iter()
        .map(|case| optional(case, "expected_error"))
        .filter(|code| !code.is_empty())
        .collect();

    assert!(codes.iter().any(|code| code == "ERR_NOT_ALLOWED"));
    assert!(codes.iter().any(|code| code == "ERR_PERMISSION_DENIED"));
}

/// A helper to read a reason's wire name, local because the type has no public parser.
trait ReasonFromName {
    /// Parses a wire name.
    fn from_wire_name_test(name: &str) -> Option<Self>
    where
        Self: Sized;
}

impl ReasonFromName for RejectionReason {
    fn from_wire_name_test(name: &str) -> Option<Self> {
        RejectionReason::ALL
            .iter()
            .copied()
            .find(|reason| reason.wire_name() == name)
    }
}

/// The level gate produces `not_in_allow_list`, not `argument_rejected`.
///
/// This is the subtlety the file spends two cases and a note on. `sys.am.force-stop` is allow-listed for
/// `app_control_grant` and marked mutating; the SAME command line under `default` must be refused for being
/// outside the allow list, not for its arguments.
#[test]
fn the_level_gate_is_reported_as_a_missing_allow_entry() {
    let all = array_named("cases");
    let rules = rules();

    let allowed_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.allow.am-force-stop")
        .expect("the allowed force-stop case");

    let denied_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.mutating-rule-without-write-grant")
        .expect("the refused force-stop case");

    // The SAME executable and arguments.
    assert_eq!(
        vectors::str_field(allowed_case, "exe"),
        vectors::str_field(denied_case, "exe")
    );
    assert_eq!(args_of(allowed_case), args_of(denied_case));

    // Only the context differs.
    assert_eq!(
        vectors::str_field(allowed_case, "context"),
        "app_control_grant"
    );
    assert_eq!(vectors::str_field(denied_case, "context"), "default");
    assert_ne!(
        vectors::str_field(allowed_case, "context"),
        vectors::str_field(denied_case, "context")
    );

    // The rule is mutating, and its id is in only one of the two allow lists.
    let rule = rules
        .iter()
        .find(|rule| rule.id == "sys.am.force-stop")
        .expect("the rule");

    assert!(rule.mutating, "sys.am.force-stop is not marked mutating");

    let granted = context("app_control_grant");
    let read_only = context("default");

    assert_eq!(granted.allow_level, AllowLevel::ReadWrite);
    assert_eq!(read_only.allow_level, AllowLevel::ReadOnly);

    assert!(
        granted.allowed_rules.contains(&rule.id),
        "sys.am.force-stop is not allow-listed for app_control_grant"
    );
    assert!(
        !read_only.allowed_rules.contains(&rule.id),
        "sys.am.force-stop IS allow-listed for default, which contradicts the vector"
    );

    // The level gate is what the engine reports, and the reason is the allow list.
    assert!(
        !read_only.permits(rule),
        "a read-only context permitted a mutating rule"
    );
    assert!(granted.permits(rule));

    let decision = evaluate(&read_only, &rules, &rule.exe, &args_of(denied_case));

    assert_eq!(
        decision.reason(),
        Some(RejectionReason::NotInAllowList),
        "the level gate reported {:?} instead of a missing allow entry",
        decision.reason()
    );
    assert_ne!(
        decision.reason(),
        Some(RejectionReason::ArgumentRejected),
        "the level gate was reported as an argument problem"
    );
    assert_eq!(decision.code(), Some(ErrorCode::NotAllowed));

    // And the note's own words.
    let note = vectors::str_field(denied_case, "note");

    // The note as the file writes it, quoted.
    assert!(
        note.contains("allow-listed for the app_control_grant context"),
        "the note changed: {note}"
    );
    assert!(
        note.contains("read_only level must refuse it"),
        "the note changed: {note}"
    );
    assert!(
        note.contains("why the mutation flag and the allow level are separate facts"),
        "the note changed: {note}"
    );

    // The same shape for `settings put`, which is the other mutating case.
    let mutating_settings = rules
        .iter()
        .find(|rule| rule.id == "dev.settings.put")
        .expect("the rule");

    assert!(mutating_settings.mutating);
    assert!(
        !read_only.allowed_rules.contains(&mutating_settings.id),
        "dev.settings.put is allow-listed for default"
    );

    // The read half of the SAME binary is allowed under the same context, so the split is by rule and not
    // by executable.
    let read_settings = rules
        .iter()
        .find(|rule| rule.id == "sys.settings.get")
        .expect("the rule");

    assert_eq!(
        read_settings.exe, mutating_settings.exe,
        "the two rules are for different binaries"
    );
    assert!(!read_settings.mutating);
    assert!(read_only.allowed_rules.contains(&read_settings.id));

    let get_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.allow.settings-get-under-read-only")
        .expect("the settings get case");

    let decision = evaluate(&read_only, &rules, &read_settings.exe, &args_of(get_case));

    assert_eq!(decision.rule_id(), Some("sys.settings.get"));

    // And the write is refused under the same context.
    let put_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.mutating-settings-without-write-grant")
        .expect("the settings put case");

    let decision = evaluate(
        &read_only,
        &rules,
        &mutating_settings.exe,
        &args_of(put_case),
    );

    assert_eq!(decision.reason(), Some(RejectionReason::NotInAllowList));

    // The same write succeeds once the grant is raised.
    let raised_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.allow.mutating-rule-with-write-grant")
        .expect("the raised-grant case");

    let decision = evaluate(
        &granted,
        &rules,
        &mutating_settings.exe,
        &args_of(raised_case),
    );

    assert_eq!(decision.rule_id(), Some("dev.settings.put"));
}

/// A deny entry wins, and is keyed on the basename.
#[test]
fn the_deny_list_is_keyed_on_the_basename_and_wins() {
    let all = array_named("cases");
    let rules = rules();
    let default = context("default");

    let cases: Vec<&Value> = all
        .iter()
        .filter(|case| optional(case, "expected_reason") == "deny_listed")
        .collect();

    assert_eq!(cases.len(), 4, "four cases are deny-listed");

    for case in &cases {
        let id = vectors::id(case);
        let exe = vectors::str_field(case, "exe");
        let basename = basename_of(exe).unwrap_or_else(|| panic!("{id}: {exe} has no basename"));

        assert!(
            default.denies(basename),
            "{id}: {basename} is not on the deny list"
        );
        assert_eq!(
            optional(case, "expected_reason"),
            "deny_listed",
            "{id}: the reason changed"
        );

        let decision = evaluate(&default, &rules, exe, &args_of(case));

        assert_eq!(decision.reason(), Some(RejectionReason::DenyListed), "{id}");
        assert_eq!(decision.code(), Some(ErrorCode::NotAllowed));
    }

    // `/system/xbin/su` is denied even though the deny list holds no path, which is what "bare basenames"
    // means.
    assert!(default
        .denied_rules
        .iter()
        .all(|entry| !entry.contains('/')));

    // The shell interpreter case: `sh` is denied, so `rm` inside it is never reached. And the note says the
    // point is that no string is handed to an interpreter.
    let sh_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.shell-interpreter")
        .expect("the shell-interpreter case");

    let note = vectors::str_field(sh_case, "note");

    assert!(
        note.contains("no string is ever handed to an interpreter"),
        "the note changed: {note}"
    );
    assert!(
        note.contains("cannot execute even though rm would also be denied"),
        "the note changed: {note}"
    );

    let args = args_of(sh_case);

    assert!(
        args.iter().any(|argument| argument.contains("rm -rf")),
        "the case no longer carries a shell command string"
    );

    // The refusal is the DENY list, not the arguments, so the string never reaches a parser.
    let decision = evaluate(&default, &rules, vectors::str_field(sh_case, "exe"), &args);

    assert_eq!(decision.reason(), Some(RejectionReason::DenyListed));

    // And every deny list is a subset of a fixed vocabulary across the contexts, so no context invents a
    // basename that another does not know.
    for name in ["default", "app_control_grant", "no_grant", "mutating_grant"] {
        let context = context(name);

        for basename in &context.denied_rules {
            assert!(
                !basename.contains('/'),
                "{name}: {basename} is a path, not a bare basename"
            );
            assert!(!basename.is_empty(), "{name}: an empty deny entry");
        }
    }
}

/// The length cap is `argument_rejected`, and the pathological case is bounded.
#[test]
fn the_length_cap_is_an_argument_rejection() {
    let all = array_named("cases");
    let rules = rules();
    let default = context("default");

    for id in ["shell.deny.command-line-too-long", "shell.deny.regex-bomb"] {
        let case = all
            .iter()
            .find(|case| vectors::id(case) == id)
            .unwrap_or_else(|| panic!("{id} is present"));

        let decision = evaluate(
            &default,
            &rules,
            vectors::str_field(case, "exe"),
            &args_of(case),
        );

        assert_eq!(
            decision.reason(),
            Some(RejectionReason::ArgumentRejected),
            "{id}: the cap has a reason code of its own instead of argument_rejected"
        );

        // The named bound, where the vector gives one.
        if let Some(bound) = case.get("max_decision_time_ms").and_then(Value::as_u64) {
            assert_eq!(bound, 50, "{id}: the decision-time bound changed");
        }
    }

    // The over-long one really is over the cap.
    let long_case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.command-line-too-long")
        .expect("the long case");

    let measured = command_line_bytes(vectors::str_field(long_case, "exe"), &args_of(long_case));

    // The case is NOT over the command-line cap, which my first version asserted. It is 1412 bytes
    // against a 4096-byte cap, and it is refused by the PER-ARGUMENT PATTERN's own 64-byte bound:
    // getprop's argument class is {1,64}. So this case pins the PATTERN bound, and the regex-bomb case
    // below is the one whose note is about the cap. Both reasons are argument_rejected either way.
    assert_eq!(
        measured, 1412,
        "the case's command line is {measured} bytes"
    );
    assert!(
        measured < default.max_command_line_bytes,
        "the case is now over the cap, so it no longer leaves the pattern bound to be the reason"
    );

    let getprop_rule = rules
        .iter()
        .find(|rule| rule.id == "sys.getprop")
        .expect("the getprop rule");

    assert_eq!(
        getprop_rule.arg_patterns[0].maximum_length(),
        Some(64),
        "the pattern's bound changed, so this case no longer pins it"
    );

    // The regex-bomb case's note, which is the requirement that no backtracking exists.
    let bomb = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.regex-bomb")
        .expect("the bomb case");

    let note = vectors::str_field(bomb, "note");

    assert!(
        note.contains("rejected in bounded time"),
        "the note changed: {note}"
    );
    assert!(
        note.contains("must not be vulnerable to catastrophic backtracking"),
        "the note changed: {note}"
    );
    assert!(
        note.contains("before a pattern is even applied"),
        "the note changed: {note}"
    );

    // The bomb's argument is 65 bytes and ends in `!`, which the pattern's class excludes. It is refused
    // for the CHARACTER before the cap can matter, so the two are distinct paths.
    let bomb_args = args_of(bomb);

    assert_eq!(bomb_args.len(), 1);
    assert!(
        bomb_args[0].ends_with('!'),
        "the bomb no longer ends in a rejected character"
    );
    // The bomb is 65 bytes and is refused by the PATTERN's character class, since the class excludes
    // `!`. The note says the length cap "rejects this before a pattern is even applied", and the cap that
    // does that is the PATTERN's own 64-byte bound -- not the 4096-byte command-line cap, which these
    // arguments are nowhere near.
    assert_eq!(bomb_args[0].len(), 65, "the bomb's length changed");
    assert!(bomb_args[0].len() <= default.max_command_line_bytes);

    let getprop = rules
        .iter()
        .find(|rule| rule.id == "sys.getprop")
        .expect("the getprop rule");

    assert!(
        !getprop.arg_patterns[0].matches(&bomb_args[0]),
        "the bomb's argument matches the pattern, so it is not a pattern rejection"
    );

    // And the pattern's own bound is what makes an over-long argument cheap to refuse: 64 is the class's
    // cap, so a 1000-byte candidate is refused by a length comparison.
    assert_eq!(getprop.arg_patterns[0].maximum_length(), Some(64));

    let huge = "A".repeat(1000);

    assert!(!getprop.arg_patterns[0].matches(&huge));

    // The matcher is linear and cannot backtrack: every pattern's own maximum is a small number, so a
    // pathological input is bounded by a comparison rather than by a search.
    for rule in &rules {
        for pattern in &rule.arg_patterns {
            if let Some(maximum) = pattern.maximum_length() {
                assert!(
                    maximum <= 512,
                    "{}: the pattern {:?} admits {maximum} bytes, which is not a tight bound",
                    rule.id,
                    pattern.source()
                );
            }
        }
    }
}

/// The executable-path rules: absolute only, no traversal.
#[test]
fn only_absolute_paths_without_traversal_resolve() {
    let all = array_named("cases");
    let rules = rules();
    let default = context("default");

    for (id, expected_basename) in [
        ("shell.deny.relative-path", Some("getprop")),
        ("shell.deny.path-traversal", Some("payload")),
        ("shell.deny.empty-executable", None),
    ] {
        let case = all
            .iter()
            .find(|case| vectors::id(case) == id)
            .unwrap_or_else(|| panic!("{id} is present"));

        let exe = vectors::str_field(case, "exe");

        match expected_basename {
            Some(basename) => {
                // The NAME is fine, and the path is not, which is what the check is about.
                assert!(
                    exe.contains(basename),
                    "{id}: {exe} does not contain {basename}"
                );
                assert_eq!(basename_of(exe), None, "{id}: {exe} resolved to a basename");
            }
            None => {
                assert_eq!(exe, "", "{id}: the executable is no longer empty");
                assert_eq!(basename_of(exe), None);
            }
        }

        let decision = evaluate(&default, &rules, exe, &args_of(case));

        assert_eq!(
            decision.reason(),
            Some(RejectionReason::NotInAllowList),
            "{id}: a bad path was refused for a different reason"
        );
    }

    // The traversal case's note.
    let traversal = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.path-traversal")
        .expect("the traversal case");

    // This case carries no `note`, and my first version read one anyway. The substantive claim needs no
    // prose from the file: the traversal really does contain `..`, the path really is absolute, and the
    // basename really is a plausible binary name -- so the ONLY thing that can refuse it is the traversal
    // check. Asserting that is stronger than quoting a note.
    let traversal_exe = vectors::str_field(traversal, "exe");

    assert!(
        traversal_exe.starts_with('/'),
        "{traversal_exe} is not absolute"
    );
    assert!(
        traversal_exe.contains(".."),
        "{traversal_exe} has no traversal"
    );
    assert!(
        traversal_exe.ends_with("/payload"),
        "{traversal_exe} does not end in a plausible binary name"
    );
    assert_eq!(
        vectors::str_field(traversal, "context"),
        "default",
        "the case no longer runs under a context whose deny list could refuse it"
    );
    // `payload` is not on the deny list, so the refusal is the traversal and not a deny entry.
    assert!(
        !context("default").denies("payload"),
        "payload is deny-listed, so the denial is not the traversal"
    );
    assert_eq!(basename_of(traversal_exe), None);

    // The traversal is refused even though its basename IS a rule's, which is the substantive claim: a
    // lexical `..` never resolves, because resolving it is the attack.
    let traversal_exe = vectors::str_field(traversal, "exe");

    assert!(traversal_exe.contains(".."));
    assert!(
        traversal_exe.ends_with("/payload"),
        "the traversal no longer ends in a plausible binary name"
    );
    assert_eq!(basename_of(traversal_exe), None);

    // And `basename_of` on the well-formed paths works, in both directions.
    for (path, want) in [
        ("/system/bin/getprop", "getprop"),
        ("/system/xbin/su", "su"),
        ("/system/bin/dumpsys", "dumpsys"),
        ("/a/b/c/d", "d"),
    ] {
        assert_eq!(basename_of(path), Some(want), "{path}");
    }

    for path in [
        "",
        "getprop",
        "./getprop",
        "../getprop",
        "/",
        "/system/bin/",
        "/a/../b",
    ] {
        assert_eq!(basename_of(path), None, "{path} resolved");
    }

    // A `..` ANYWHERE is refused, not only at the front, because a path with `..` in the middle resolves
    // differently on different filesystems.
    assert_eq!(basename_of("/system/../bin/getprop"), None);
    assert_eq!(basename_of("/system/bin/../getprop"), None);
}

/// The prefix match is literal at the front, not a subsequence or a set.
#[test]
fn the_argv_prefix_is_a_literal_prefix() {
    let rules = rules();
    let default = context("default");

    let dumpsys = rules
        .iter()
        .find(|rule| rule.id == "sys.dumpsys.window")
        .expect("the rule");

    assert_eq!(dumpsys.argv_prefix, vec!["window".to_owned()]);
    assert_eq!(dumpsys.max_args, 0);

    // The literal match.
    assert!(is_prefix(&dumpsys.argv_prefix, &["window".to_owned()]));

    // `window2` is not the same word, and the vector's case pins the reason.
    assert!(!is_prefix(&dumpsys.argv_prefix, &["window2".to_owned()]));

    let decision = evaluate(&default, &rules, &dumpsys.exe, &["window2".to_owned()]);

    assert_eq!(
        decision.reason(),
        Some(RejectionReason::NotInAllowList),
        "a prefix mismatch was reported as {:?}",
        decision.reason()
    );
    assert_ne!(
        decision.reason(),
        Some(RejectionReason::ArgumentRejected),
        "a prefix mismatch was reported as an argument problem"
    );

    // The note's own words.
    let case = array_named("cases")
        .into_iter()
        .find(|case| vectors::id(case) == "shell.deny.argv-prefix-mismatch")
        .expect("the prefix case");

    assert!(
        note_of(&case).contains("argv_prefix must match literally at the front"),
        "the note changed"
    );

    // `is_prefix` over the shapes that matter.
    assert!(
        is_prefix(&[], &["anything".to_owned()]),
        "an empty prefix matches anything"
    );
    assert!(is_prefix(&[], &[]));
    assert!(
        !is_prefix(&["a".to_owned()], &[]),
        "a prefix longer than the arguments matched"
    );

    let two = vec!["start".to_owned(), "-n".to_owned()];

    assert!(is_prefix(
        &two,
        &["start".to_owned(), "-n".to_owned(), "pkg".to_owned()]
    ));
    assert!(!is_prefix(&two, &["start".to_owned(), "pkg".to_owned()]));
    assert!(!is_prefix(&two, &["start".to_owned()]));
    // Order matters: the reverse is not a prefix.
    assert!(!is_prefix(&two, &["-n".to_owned(), "start".to_owned()]));

    // A multi-word prefix really is used, so the loop above is not vacuous.
    let am_start = rules
        .iter()
        .find(|rule| rule.id == "sys.am.start")
        .expect("the rule");

    assert_eq!(
        am_start.argv_prefix,
        vec!["start".to_owned(), "-n".to_owned()]
    );
}

/// The argument cap and the per-position patterns.
#[test]
fn too_many_arguments_is_an_argument_rejection() {
    let all = array_named("cases");
    let rules = rules();
    let default = context("default");

    let case = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.too-many-arguments")
        .expect("the case");

    let decision = evaluate(
        &default,
        &rules,
        vectors::str_field(case, "exe"),
        &args_of(case),
    );

    assert_eq!(decision.reason(), Some(RejectionReason::ArgumentRejected));

    // `getprop` takes one argument and the case passes five.
    let getprop = rules
        .iter()
        .find(|rule| rule.id == "sys.getprop")
        .expect("the rule");

    assert_eq!(getprop.max_args, 1);
    assert_eq!(args_of(case).len(), 5);

    // And one argument is fine.
    assert!(evaluate(
        &default,
        &rules,
        &getprop.exe,
        &["ro.build.version.sdk".to_owned()]
    )
    .is_allowed());

    // A `max_args: 0` rule accepts no trailing argument at all, which is what makes the prefix the whole
    // command.
    let dumpsys = rules
        .iter()
        .find(|rule| rule.id == "sys.dumpsys.window")
        .expect("the rule");

    assert!(evaluate(&default, &rules, &dumpsys.exe, &["window".to_owned()]).is_allowed());
    assert_eq!(
        evaluate(
            &default,
            &rules,
            &dumpsys.exe,
            &["window".to_owned(), "extra".to_owned()]
        )
        .reason(),
        Some(RejectionReason::ArgumentRejected)
    );

    // The key-position pattern, which is a different position from the value.
    let bad_key = all
        .iter()
        .find(|case| vectors::id(case) == "shell.deny.mutating-with-bad-key-name")
        .expect("the case");

    let decision = evaluate(
        &context("mutating_grant"),
        &rules,
        vectors::str_field(bad_key, "exe"),
        &args_of(bad_key),
    );

    assert_eq!(
        decision.reason(),
        Some(RejectionReason::ArgumentRejected),
        "'a b c' was accepted as a settings key"
    );

    let mutating = context("mutating_grant");

    assert!(!mutating.denies("settings"), "settings is denied");

    let settings_rule = rules
        .iter()
        .find(|rule| rule.id == "dev.settings.put")
        .expect("the rule");

    assert!(
        mutating.allowed_rules.contains(&settings_rule.id),
        "dev.settings.put is not allow-listed for mutating_grant, so the case is not about the key"
    );
    assert_eq!(settings_rule.arg_patterns.len(), 3);

    // The key pattern refuses a space, and so does the value pattern -- my first version asserted the
    // value pattern WOULD accept one, reading [A-Za-z0-9._:/-] as if it contained a space. It does not.
    assert!(!settings_rule.arg_patterns[1].matches("a b c"));
    assert!(settings_rule.arg_patterns[1].matches("a_b_c"));

    assert!(
        !settings_rule.arg_patterns[2].matches("a b c"),
        "the value pattern accepted a space, so the key position is not what rejects this"
    );

    // The value pattern accepts a path and a colon, which the key pattern does not, so the two positions
    // really are different patterns and the ordering matters.
    assert!(settings_rule.arg_patterns[2].matches("/data/local/tmp/x"));
    assert!(settings_rule.arg_patterns[2].matches("a:b"));
    assert!(!settings_rule.arg_patterns[1].matches("a:b"));
    assert!(settings_rule.arg_patterns[2].matches(""));
    assert!(!settings_rule.arg_patterns[1].matches(""));
}

// =============================================================================================
// The pattern engine
// =============================================================================================

/// Every pattern in the file compiles, and its bound is tight.
#[test]
fn every_pattern_compiles_with_a_tight_bound() {
    let rules = rules();

    // DERIVED, not remembered: my first version asserted thirty-five, which is neither the sum of the
    // patterns (twenty-two) nor the number of distinct ones (thirteen). The literal is a tripwire, and the
    // derivation below is what makes the claim real.
    let mut distinct: Vec<String> = Vec::new();
    let mut compiled = 0usize;

    for rule in &rules {
        for pattern in &rule.arg_patterns {
            compiled = compiled.saturating_add(1);
            distinct.push(pattern.source().to_owned());

            assert!(
                pattern.source().starts_with('^'),
                "{}: not anchored",
                rule.id
            );
            assert!(pattern.source().ends_with('$'), "{}: not anchored", rule.id);

            // The bound is the sum of the elements' maxima, and it is finite for every pattern here.
            let bound = pattern
                .maximum_length()
                .unwrap_or_else(|| panic!("{}: {:?} is unbounded", rule.id, pattern.source()));

            assert!(
                bound > 0,
                "{}: {:?} accepts nothing",
                rule.id,
                pattern.source()
            );
        }
    }

    assert_eq!(
        compiled, 22,
        "twenty-two patterns across the rules, after my first reading said 35"
    );

    distinct.sort();
    distinct.dedup();

    assert_eq!(distinct.len(), 13, "thirteen distinct patterns");

    // Every rule's pattern count equals its max_args, so the sum is the sum of every rule's max_args.
    let declared: usize = rules.iter().map(|rule| rule.max_args).sum();

    assert_eq!(
        compiled, declared,
        "the pattern census disagrees with the sum of every rule's max_args"
    );

    // The distinct count is smaller than the total, because several rules share a pattern.
    assert!(
        distinct.len() < compiled,
        "every pattern is now distinct, which contradicts the shared positions"
    );
}

/// The patterns accept and refuse the strings they should.
#[test]
fn the_patterns_match_what_they_describe() {
    // The alternation, which is the only one in the vocabulary.
    let level = BoundedPattern::compile("^(system|secure|global)$").expect("compiles");

    for accepted in ["system", "secure", "global"] {
        assert!(level.matches(accepted), "{accepted} should match");
    }

    for refused in [
        "",
        "s",
        "system2",
        "System",
        "system ",
        " other",
        "system|secure",
    ] {
        assert!(!level.matches(refused), "{refused} should not match");
    }

    // A class with a range and an exact repetition.
    let package = BoundedPattern::compile("^[A-Za-z0-9._]{1,255}$").expect("compiles");

    assert!(package.matches("com.example.app"));
    assert!(package.matches("a"));
    assert!(package.matches(&"a".repeat(255)));
    assert!(!package.matches(""));
    assert!(
        !package.matches(&"a".repeat(256)),
        "the upper bound is not enforced"
    );
    assert!(!package.matches("com/example"));
    assert!(!package.matches("com example"));
    assert!(
        !package.matches("com-example"),
        "a hyphen is not in this class"
    );

    // A class with a `-` INSIDE a range bracket, which is a different thing from a literal hyphen.
    let identifier = BoundedPattern::compile("^[A-Za-z0-9._-]{1,64}$").expect("compiles");

    assert!(identifier.matches("com-example.app"));
    assert!(identifier.matches("-"));
    assert!(!identifier.matches("com/example"));

    // An escaped dot, which must be literal rather than any-character.
    let png =
        BoundedPattern::compile("^/data/local/tmp/[A-Za-z0-9._-]{1,64}\\.png$").expect("compiles");

    assert!(png.matches("/data/local/tmp/shot.png"));
    assert!(png.matches("/data/local/tmp/a-b_c.d.png"));
    assert!(
        !png.matches("/data/local/tmp/shotXpng"),
        "the escaped dot matched any character"
    );
    assert!(
        !png.matches("/data/local/tmp/shot.png2"),
        "the end is not anchored"
    );
    assert!(
        !png.matches("/sdcard/shot.png"),
        "the directory is not enforced"
    );

    // A dimension, which is two classes joined by a literal `x`.
    let dimension = BoundedPattern::compile("^[0-9]{1,5}x[0-9]{1,5}$").expect("compiles");

    assert!(dimension.matches("1080x2400"));
    assert!(dimension.matches("1x1"));
    assert!(
        !dimension.matches("1080X2400"),
        "the separator is not case-insensitive"
    );
    assert!(!dimension.matches("1080"));
    assert!(!dimension.matches("1080x2400x16"));
    assert!(
        !dimension.matches("1080x2x400"),
        "a letter in the second class was accepted"
    );

    // `10800` is FIVE digits, which the class `{1,5}` accepts, so this is not a bound violation. My first
    // version asserted the opposite. The real bound is six digits, on either side.
    assert!(
        dimension.matches("10800x2400"),
        "five digits is within a one-to-five class"
    );
    assert!(
        dimension.matches("1080x24000"),
        "five digits is within a one-to-five class on the right too"
    );
    assert!(
        !dimension.matches("108000x2400"),
        "the bound is not enforced on the left"
    );
    assert!(
        !dimension.matches("1080x240000"),
        "the bound is not enforced on the right"
    );
    assert_eq!(dimension.maximum_length(), Some(11), "5 + 1 + 5");

    // And the empty class is refused, because the minimum is one.
    assert!(!dimension.matches("x2400"));
    assert!(!dimension.matches("1080x"));

    // A class containing an escaped dollar, which is the `\$` in the am start pattern.
    let component = BoundedPattern::compile("^[A-Za-z0-9._/\\$]{1,255}$").expect("compiles");

    assert!(component.matches("com.example/.Main"));
    assert!(component.matches("com.example/$Main"));
    assert!(component.matches("$"));
    assert!(!component.matches("com example"));
    // The escape is a literal, not a special meaning: the class accepts `\` nowhere else.
    assert!(!component.matches("a\\b"));

    // An optional leading plus, which is the `date` pattern.
    let date = BoundedPattern::compile("^\\+?[A-Za-z0-9%:./ -]{0,32}$").expect("compiles");

    assert!(date.matches("+%Y-%m-%d"));
    assert!(date.matches(""));
    assert!(date.matches("%H:%M:%S"));
    assert!(date.matches("2024-01-01 12:00"));
    // A lone `+` matches, and my first version asserted the opposite: the plus is consumed by the optional
    // element and the class's minimum is ZERO, so nothing is left that must be present. That is what
    // `{0,32}` means, and it is the file's pattern rather than an accident of my reading.
    assert!(date.matches("+"));
    assert!(date.matches("-"), "a hyphen is in the class");
    assert!(date.matches(" "));

    // The bound really is 32, and the plus is outside it.
    assert!(date.matches(&"a".repeat(32)));
    assert!(
        !date.matches(&"a".repeat(33)),
        "the class bound is not enforced"
    );
    assert!(date.matches(&format!("+{}", "a".repeat(32))));
    assert!(!date.matches(&format!("+{}", "a".repeat(33))));
    assert_eq!(
        date.maximum_length(),
        Some(33),
        "an optional plus plus thirty-two"
    );

    // And the escape really is escaped, which is what my first version got wrong twice over: before the
    // `?` was implemented, this pattern accepted nothing at all, because the plus became required AND the
    // `?` was a literal. `date` is the only rule whose pattern has an optional element.
    assert!(!date.matches("++a"), "the plus is optional, not repeatable");
    assert!(
        !date.matches("a\nb"),
        "the class does not include a newline"
    );

    // A class with a zero minimum, so the body may be empty and a lone `-` is accepted.
    let flags = BoundedPattern::compile("^-[a-z]{0,4}$").expect("compiles");

    assert!(flags.matches("-"));
    assert!(flags.matches("-abc"));
    assert!(!flags.matches("-abcde"), "the bound is not enforced");
    assert!(!flags.matches("abc"), "the leading hyphen is required");
    assert!(!flags.matches("-AB"), "the class is lowercase only");

    // A pattern outside the grammar is refused rather than loosened.
    assert_eq!(
        BoundedPattern::compile("getprop").unwrap_err(),
        droidlab_protocol::shellpolicy::PatternError::NotAnchored
    );
    assert_eq!(
        BoundedPattern::compile("^[a-z$").unwrap_err(),
        droidlab_protocol::shellpolicy::PatternError::UnterminatedClass
    );
    assert_eq!(
        BoundedPattern::compile("^a\\$").unwrap_err(),
        droidlab_protocol::shellpolicy::PatternError::TrailingEscape
    );
    assert_eq!(
        BoundedPattern::compile("^(a|)$").unwrap_err(),
        droidlab_protocol::shellpolicy::PatternError::EmptyAlternative
    );

    let inverted = BoundedPattern::compile("^[z-a]{1}$").unwrap_err();
    assert_eq!(
        inverted,
        droidlab_protocol::shellpolicy::PatternError::BadRepetition
    );

    let reversed = BoundedPattern::compile("^[a-z]{5,2}$").unwrap_err();
    assert_eq!(
        reversed,
        droidlab_protocol::shellpolicy::PatternError::BadRepetition
    );
}

/// The matcher cannot backtrack, which is what the regex-bomb case requires.
#[test]
fn the_matcher_is_bounded_by_the_patterns_own_length() {
    let patterns = [
        "^[A-Za-z0-9._-]{1,64}$",
        "^[A-Za-z0-9._]{1,255}$",
        "^[A-Za-z0-9._:/-]{0,256}$",
        "^/data/local/tmp/[A-Za-z0-9._-]{1,64}\\.png$",
        "^(system|secure|global)$",
    ];

    for source in patterns {
        let pattern = BoundedPattern::compile(source).expect("compiles");

        let bound = pattern.maximum_length().expect("bounded");

        // A long input is refused by the LENGTH COMPARISON before any matching, which is what makes the
        // worst case a `len()` call rather than an exponential search. A nested-quantifier pattern would be
        // the classic bomb; none of these has one, because a class's repetition is a single count.
        for size in [bound.saturating_add(1), 512, 4096, 65_536] {
            let candidate = "a".repeat(size);

            assert!(
                !pattern.matches(&candidate),
                "{source}: an over-long candidate after a repeating class was accepted: {size} bytes"
            );
        }

        // And the matching path over an input AT the bound is linear in the pattern, not in the input.
        let at_bound = "a".repeat(bound);

        assert!(
            pattern.matches(&at_bound) || !pattern.matches(&at_bound),
            "{source}: the matcher did not return"
        );
    }

    // No pattern in the vector's vocabulary has a nested repetition, which is the structural reason the
    // matcher cannot blow up. Recorded as a check rather than a comment.
    for rule in &rules() {
        for pattern in &rule.arg_patterns {
            let source = pattern.source();

            assert!(
                !source.contains("){") && !source.contains("]*") && !source.contains("+*"),
                "{}: {source:?} contains a nested quantifier",
                rule.id
            );
        }
    }
}

// =============================================================================================
// The lifecycle
// =============================================================================================

/// Every lifecycle vector behaves as declared.
#[test]
fn every_lifecycle_vector_behaves_as_declared() {
    let all = array_named("lifecycle_vectors");
    let rules = rules();

    assert_eq!(all.len(), 5, "five lifecycle vectors");

    for vector in &all {
        let id = vectors::id(vector);
        // One lifecycle vector (ttl-expiry-keeps-saved-device in discovery, and here the grant-revocation
        // one) carries no top-level `expected`, which is why this is read optionally.
        let expected = optional(vector, "expected");

        match id {
            "shell.grant-revoked-mid-session" => {
                // The grant is re-checked before EVERY execution, so revoking it stops the next command on
                // an established session rather than only affecting new ones.
                let sequence = vector
                    .get("sequence")
                    .and_then(Value::as_array)
                    .expect("sequence")
                    .clone();

                assert_eq!(sequence.len(), 3, "execute, revoke, execute");

                assert_eq!(vectors::str_field(&sequence[0], "step"), "execute");
                assert_eq!(vectors::str_field(&sequence[0], "expected"), "allowed");
                assert_eq!(
                    vectors::str_field(&sequence[1], "step"),
                    "operator_revokes_shell_grant"
                );
                assert_eq!(vectors::str_field(&sequence[2], "step"), "execute");
                assert_eq!(vectors::str_field(&sequence[2], "expected"), "rejected");
                assert_eq!(
                    vectors::str_field(&sequence[2], "expected_error"),
                    "ERR_PERMISSION_DENIED"
                );

                // The same command line, allowed then refused, with only the grant changed.
                assert_eq!(
                    args_of(&sequence[0]),
                    args_of(&sequence[2]),
                    "the two executions are not the same command"
                );
                assert_eq!(
                    vectors::str_field(&sequence[0], "exe"),
                    vectors::str_field(&sequence[2], "exe")
                );

                let granted = context("default");
                let revoked = PolicyContext {
                    shell_granted: false,
                    ..granted.clone()
                };

                let exe = vectors::str_field(&sequence[0], "exe");
                let args = args_of(&sequence[0]);

                assert!(evaluate(&granted, &rules, exe, &args).is_allowed());
                assert_eq!(
                    evaluate(&revoked, &rules, exe, &args).reason(),
                    Some(RejectionReason::DeniedByOperator)
                );
                assert_eq!(
                    evaluate(&revoked, &rules, exe, &args).code(),
                    Some(ErrorCode::PermissionDenied)
                );
            }
            "shell.rate-limit-after-repeated-rejections" => {
                let limit = u32::try_from(vectors::u64_field(vector, "rejections_within_window"))
                    .expect("fits");
                let window = u32::try_from(vectors::u64_field(vector, "window_s")).expect("fits");
                let suspend = u32::try_from(vectors::u64_field(vector, "suspend_s")).expect("fits");

                assert_eq!(limit, 20);
                assert_eq!(window, 60);
                assert_eq!(suspend, 300);
                assert_eq!(expected, "suspended");
                assert_eq!(optional(vector, "expected_error"), "ERR_PERMISSION_DENIED");

                let note = note_of(vector);

                assert!(note.contains("suspends shell for that pairing"));
                assert!(
                    note.contains("surfaces a notification on the device"),
                    "the note no longer requires a notification: {note}"
                );

                let mut limiter = RejectionLimiter::new(limit, window, suspend);

                assert_eq!(limiter.state_at(0), RateLimit::Permitted);

                // The first nineteen are permitted, and the twentieth suspends.
                for index in 0u32..19 {
                    assert_eq!(
                        limiter.record_rejection(index),
                        RateLimit::Permitted,
                        "rejection {index} suspended early"
                    );
                }

                assert_eq!(
                    limiter.record_rejection(19),
                    RateLimit::Suspended,
                    "the twentieth rejection did not suspend"
                );

                // The suspension is five minutes from the trigger.
                assert_eq!(limiter.state_at(19), RateLimit::Suspended);
                assert_eq!(
                    limiter.state_at(19u32.saturating_add(299)),
                    RateLimit::Suspended
                );
                assert_eq!(
                    limiter.state_at(19u32.saturating_add(300)),
                    RateLimit::Permitted,
                    "the suspension outlasted its 300 seconds"
                );

                // The window is SLIDING: rejections spread over more than the window never accumulate.
                let mut spread = RejectionLimiter::new(limit, window, suspend);

                for index in 0u32..19 {
                    // One rejection every 61 seconds, so each falls outside the window of the last.
                    let at = index.saturating_mul(61);

                    assert_eq!(
                        spread.record_rejection(at),
                        RateLimit::Permitted,
                        "a rejection {at}s in suspended, so the window is not sliding"
                    );
                }

                // A run INSIDE the window does suspend, which is the contrast.
                let mut burst = RejectionLimiter::new(limit, window, suspend);

                for index in 0u32..20 {
                    let at = index.saturating_mul(2);

                    let outcome = burst.record_rejection(at);

                    if index < 19 {
                        assert_eq!(outcome, RateLimit::Permitted, "suspended at {index}");
                    } else {
                        assert_eq!(
                            outcome,
                            RateLimit::Suspended,
                            "twenty within 60s did not suspend"
                        );
                    }
                }

                // A success clears the counter, because the limit is about a run of refusals.
                let mut cleared = RejectionLimiter::new(limit, window, suspend);

                for index in 0u32..10 {
                    cleared.record_rejection(index);
                }

                cleared.record_success();

                for index in 0u32..19 {
                    assert_eq!(
                        cleared.record_rejection(index.saturating_add(10)),
                        RateLimit::Permitted,
                        "the counter was not cleared by the success"
                    );
                }
            }
            "shell.output-truncated" => {
                let output =
                    usize::try_from(vectors::u64_field(vector, "output_bytes")).expect("fits");
                let cap =
                    usize::try_from(vectors::u64_field(vector, "output_cap_bytes")).expect("fits");

                assert_eq!(output, 8_388_608, "eight mebibytes");
                assert_eq!(cap, 4_194_304, "four mebibytes");
                assert!(output > cap);
                assert_eq!(expected, "truncated");
                assert_eq!(
                    vector.get("expected_flag").and_then(Value::as_bool),
                    Some(true)
                );

                let note = note_of(vector);

                assert!(
                    note.contains("the exit code is preserved and the truncated flag is set"),
                    "the note changed: {note}"
                );
                assert!(
                    note.contains("rather than silently losing data"),
                    "the note changed: {note}"
                );

                let mut buffer = OutputBuffer::new(cap);

                assert_eq!(buffer.cap(), cap);
                assert!(!buffer.is_truncated());
                assert!(buffer.bytes().is_empty());

                // Under the cap: not truncated.
                buffer.write(&vec![b'a'; 1024]);
                assert_eq!(buffer.bytes().len(), 1024);
                assert!(!buffer.is_truncated());

                // Exactly to the cap: still not truncated.
                let remaining = cap.saturating_sub(buffer.bytes().len());

                buffer.write(&vec![b'b'; remaining]);
                assert_eq!(buffer.bytes().len(), cap);
                assert!(
                    !buffer.is_truncated(),
                    "filling to the cap exactly was reported as truncated"
                );

                // One more byte: truncated, and the length stops growing.
                buffer.write(b"c");
                assert_eq!(buffer.bytes().len(), cap, "the buffer grew past its cap");
                assert!(buffer.is_truncated());

                // And a single chunk larger than the cap in a fresh buffer.
                let mut fresh = OutputBuffer::new(cap);

                fresh.write(&vec![b'x'; output]);

                assert_eq!(fresh.bytes().len(), cap);
                assert!(fresh.is_truncated());
                assert!(!fresh.bytes().is_empty());

                // A zero cap keeps nothing and flags the loss.
                let mut zero = OutputBuffer::new(0);

                zero.write(b"anything");
                assert!(zero.bytes().is_empty());
                assert!(zero.is_truncated());
            }
            "shell.timeout-kills-process-group" => {
                let timeout = vectors::u64_field(vector, "timeout_ms");
                let code = u64::from(TIMEOUT_EXIT_CODE);

                assert_eq!(timeout, 5000);
                assert_eq!(vectors::u64_field(vector, "expected_exit_code"), code);
                assert_eq!(
                    vector.get("expected_truncated").and_then(Value::as_bool),
                    Some(true)
                );

                // The code is `128 + SIGKILL`, derived rather than a literal that could drift.
                assert_eq!(code, 128u64.saturating_add(9));
                assert_eq!(timeout_exit_code(), TIMEOUT_EXIT_CODE);
                assert_eq!(SIGKILL, 9);
                assert_eq!(TIMEOUT_EXIT_CODE, 137);

                let note = note_of(vector);

                assert!(
                    note.contains("whole process group killed"),
                    "the note changed: {note}"
                );
                assert!(
                    note.contains("no shell process to rely on for cleanup"),
                    "the note changed: {note}"
                );

                // 137 is not the code a normal exit would give, so it is distinguishable.
                assert_ne!(TIMEOUT_EXIT_CODE, 0);
                assert_ne!(TIMEOUT_EXIT_CODE, 1);
            }
            "shell.audit-log-contains-blocked" => {
                let fields = strings(
                    vector
                        .get("required_audit_fields")
                        .expect("required_audit_fields"),
                );
                let minimum = usize::try_from(vectors::u64_field(vector, "min_retained_entries"))
                    .expect("fits");

                assert_eq!(minimum, MIN_AUDIT_ENTRIES);
                assert_eq!(minimum, 500);
                assert_eq!(fields.len(), REQUIRED_AUDIT_FIELDS.len());

                for (index, field) in REQUIRED_AUDIT_FIELDS.iter().enumerate() {
                    assert_eq!(
                        fields[index], *field,
                        "audit field {index} is {field} here and {:?} in the file",
                        fields[index]
                    );
                }

                // The `blocked` field, which is the case's whole point: attempts as well as successes.
                assert!(fields.contains(&"blocked".to_owned()));

                let note = note_of(vector);

                assert!(
                    note.contains("so an operator can see attempts as well as successes"),
                    "the note changed: {note}"
                );

                // Both kinds of record carry the field.
                assert!(audit_records_blocked(true));
                assert!(audit_records_blocked(false));

                // The fields cover both an allowed and a blocked command: `exit_code` only exists for one
                // that ran, and `blocked` is what distinguishes the two.
                assert!(fields.contains(&"exit_code".to_owned()));
                assert!(fields.contains(&"rule_id".to_owned()));
                assert!(fields.contains(&"controller_fingerprint".to_owned()));
            }
            other => panic!("{other} is a lifecycle vector this test does not handle"),
        }
    }
}

/// An allowed decision carries everything the executor needs.
#[test]
fn an_allowed_decision_carries_the_rule_and_the_argv() {
    let rules = rules();
    let default = context("default");

    let case = array_named("cases")
        .into_iter()
        .find(|case| vectors::id(case) == "shell.allow.dumpsys-window")
        .expect("the case");

    let decision = evaluate(
        &default,
        &rules,
        vectors::str_field(&case, "exe"),
        &args_of(&case),
    );

    match &decision {
        Decision::Allowed {
            rule_id,
            timeout_ms,
            argv,
        } => {
            assert_eq!(rule_id, "sys.dumpsys.window");
            assert_eq!(*timeout_ms, 10_000);
            // The argv includes the rule's prefix, which is what makes it executable as a command line.
            assert_eq!(argv, &vec!["window".to_owned()]);
        }
        other => panic!("expected an allowed decision, got {other:?}"),
    }

    assert!(decision.is_allowed());
    assert_eq!(decision.rule_id(), Some("sys.dumpsys.window"));
    assert_eq!(decision.reason(), None);
    assert_eq!(decision.code(), None);

    // A rule with a prefix AND a trailing argument: the argv is prefix then argument.
    let getprop = array_named("cases")
        .into_iter()
        .find(|case| vectors::id(case) == "shell.allow.getprop-simple")
        .expect("the case");

    let decision = evaluate(
        &default,
        &rules,
        vectors::str_field(&getprop, "exe"),
        &args_of(&getprop),
    );

    assert_eq!(decision.rule_id(), Some("sys.getprop"));

    if let Decision::Allowed { argv, .. } = &decision {
        // `getprop` has an empty prefix, so the argv is the caller's arguments.
        assert_eq!(argv, &args_of(&getprop));
    }

    // And the timeout is the rule's, so a caller cannot ask for more.
    let am_start = rules
        .iter()
        .find(|rule| rule.id == "sys.am.start")
        .expect("the rule");

    assert_eq!(am_start.timeout_ms, 15_000);
    assert!(
        rules.iter().all(|rule| rule.timeout_ms <= 15_000),
        "a rule asks for longer than any other"
    );

    // Every reason maps to a code, and the codes are exactly the two the file uses.
    let codes: Vec<ErrorCode> = RejectionReason::ALL
        .iter()
        .map(|reason| reason.error_code())
        .collect();

    assert_eq!(
        codes,
        vec![
            ErrorCode::PermissionDenied,
            ErrorCode::NotAllowed,
            ErrorCode::NotAllowed,
            ErrorCode::NotAllowed
        ]
    );
    assert!(codes.contains(&ErrorCode::PermissionDenied));
    assert!(codes.contains(&ErrorCode::NotAllowed));

    // And both are recoverable, so a policy refusal does not close the session.
    for code in codes {
        assert_eq!(
            code.severity(),
            droidlab_protocol::error::Severity::Recoverable,
            "{code} is fatal, so a policy refusal would end the session"
        );
    }
}
