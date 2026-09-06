import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Envoltórios finos de POSIX usados pelo arquivo portátil. Existem porque `FileHandle` RETÉM o
/// que já leu/escreveu (medido: 180 MB lidos em pedaços de 10 MB e descartados deixam 182 MB de
/// footprint), o que anularia o streaming — a razão de ser do `export(to:)`/`restore(from:)`.
@inline(__always) func openRead(_ path: String) -> Int32 { open(path, O_RDONLY) }
@inline(__always) func openWriteTruncate(_ path: String) -> Int32 { open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600) }
@inline(__always) func closeFD(_ fd: Int32) { _ = close(fd) }
@inline(__always) func readBytes(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ n: Int) -> Int { read(fd, buf, n) }
@inline(__always) func writeBytes(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int { write(fd, buf, n) }
