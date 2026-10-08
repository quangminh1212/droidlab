using System.Runtime.CompilerServices;

// The test assembly needs the internal big-endian readers so it can assert on
// wire encodings without those helpers becoming part of the public surface. The
// codec's public API is the protocol, and a caller that needs to poke at raw
// big-endian integers is doing something the codec should be doing for it.
[assembly: InternalsVisibleTo("DroidLab.Tests")]
