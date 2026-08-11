import Foundation
import CryptoKit

/// Erro tipado do fator-dispositivo (B6). Separa AUTENTICAÇÃO do dispositivo (evento de UX,
/// ex.: Face ID cancelado) de MATERIAL inválido (que deve colapsar em senha-errada). Definido
/// AGORA para o contrato do protocolo não mudar depois que as gavetas dependerem dele.
public enum DeviceKeystoreError: Error, Equatable {
    case authenticationCancelled     // usuário cancelou o Face ID
    case authenticationUnavailable   // enclave indisponível / biometria não configurada
    case corrupted                   // material não desembrulha (→ .wrongPasswordOrNoVault)
}

/// Fator de vínculo com o dispositivo (camada externa do envelope da MK). No iPhone real é a
/// Secure Enclave (chave não-exportável). Entra por este protocolo, sem mudar o resto do núcleo.
public protocol DeviceKeystore {
    func wrap(_ data: Data) throws -> Data
    /// Deve lançar `DeviceKeystoreError`: `.authenticationCancelled/.authenticationUnavailable`
    /// para falhas de auth do dispositivo, `.corrupted` para material inválido.
    func unwrap(_ data: Data) throws -> Data
}

#if DEBUG
/// SOMENTE dev/testes — compilado FORA em release (M4). Sem vínculo com a Secure Enclave.
public final class SoftwareDeviceKeystore: DeviceKeystore {
    private let key: SymmetricKey
    public init(key: SymmetricKey = SymmetricKey(size: .bits256)) { self.key = key }

    public func wrap(_ data: Data) throws -> Data {
        try AEAD.seal(data, key: key)
    }

    public func unwrap(_ data: Data) throws -> Data {
        guard let out = AEAD.open(data, key: key) else { throw DeviceKeystoreError.corrupted }
        return out
    }
}
#endif
