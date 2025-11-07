"""
TFHE核心加密引擎 - 基于原有功能的Agent友好包装器
"""

from typing import Dict, List, Optional, Tuple, Any, Union
import numpy as np
from numpy.random import RandomState
from numpy.typing import NDArray

from .types import (
    SecurityConfig, TFHEKeyPair, EncryptedBit, CiphertextInfo,
    SecurityLevel, GateType, OperationResult
)
from .exceptions import (
    TFHEError, KeyGenerationError, EncryptionError,
    DecryptionError, GateOperationError
)


class TFHEAgentEngine:
    """
    TFHE代理引擎 - 基于原有TFHE功能的Agent友好包装器

    设计原则：
    1. 保持与原有TFHE库的完全兼容
    2. 提供语义清晰的API便于Agent理解
    3. 添加状态跟踪和错误处理
    4. 简化复杂参数的配置
    """

    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self._keypair: Optional[TFHEKeyPair] = None
        self._rng = RandomState(seed=42)  # 固定种子便于调试

    def generate_keypair(self, security_level: SecurityLevel = SecurityLevel.STANDARD_128) -> TFHEKeyPair:
        """生成TFHE密钥对 - 基于原有tfhe_key_pair函数"""
        try:
            from .internal.keys import tfhe_key_pair, TFHEParameters

            # 根据安全级别调整参数
            params = self._get_parameters_for_security(security_level)

            # 使用原有函数生成密钥对
            secret_key, cloud_key = tfhe_key_pair(self._rng)
            self._keypair = (secret_key, cloud_key)

            return self._keypair

        except Exception as e:
            raise KeyGenerationError(f"密钥生成失败: {str(e)}")

    def encrypt_boolean(self, value: bool) -> EncryptedBit:
        """加密布尔值 - 基于原有tfhe_encrypt函数"""
        self._ensure_initialized()
        try:
            from .internal.keys import tfhe_encrypt

            # 使用原有加密函数
            message_array = np.array([value], dtype=np.bool_)
            ciphertext = tfhe_encrypt(self._rng, self._keypair[0], message_array)

            # 添加操作历史跟踪
            return self._add_operation_history(ciphertext, f"encrypt_boolean({value})")

        except Exception as e:
            raise EncryptionError(f"布尔值加密失败: {str(e)}")

    def encrypt_bit_array(self, bits: List[bool]) -> List[EncryptedBit]:
        """加密比特数组 - 批量操作"""
        return [self.encrypt_boolean(bit) for bit in bits]

    def decrypt_boolean(self, ciphertext: EncryptedBit) -> bool:
        """解密密文到布尔值 - 基于原有tfhe_decrypt函数"""
        self._ensure_initialized()
        try:
            from .internal.keys import tfhe_decrypt

            # 使用原有解密函数
            decrypted_array = tfhe_decrypt(self._keypair[0], ciphertext)
            return bool(decrypted_array[0] if hasattr(decrypted_array, '__getitem__') else decrypted_array)

        except Exception as e:
            raise DecryptionError(f"解密失败: {str(e)}")

    def get_ciphertext_info(self, ciphertext: EncryptedBit) -> CiphertextInfo:
        """获取密文信息 - 便于Agent监控状态"""
        try:
            # 从原有密文对象提取信息
            shape = getattr(ciphertext, 'shape', (1,))
            noise_level = getattr(ciphertext, 'current_variances', np.array([0]))[0]

            # 计算操作计数
            op_count = len(getattr(ciphertext, 'operation_history', []))

            # 评估健康状态
            max_noise = getattr(self._keypair[0].params, 'alpha_max', 1.0) if self._keypair else 1.0
            health_status = "healthy" if noise_level < max_noise * 0.5 else "warning"

            return CiphertextInfo(
                shape=shape,
                noise_level=float(noise_level),
                operations_count=op_count,
                security_level=self.config.security_level,
                health_status=health_status
            )

        except Exception as e:
            raise TFHEError(f"获取密文信息失败: {str(e)}")

    def create_secure_gate(self, gate_type: GateType) -> callable:
        """创建安全逻辑门 - 工厂模式便于Agent使用"""
        gate_creators = {
            GateType.NAND: self._create_nand_gate,
            GateType.AND: self._create_and_gate,
            GateType.OR: self._create_or_gate,
            GateType.XOR: self._create_xor_gate,
            GateType.NOT: self._create_not_gate,
            GateType.MUX: self._create_mux_gate,
            GateType.NOR: self._create_nor_gate,
            GateType.XNOR: self._create_xnor_gate
        }

        if gate_type not in gate_creators:
            raise ValueError(f"不支持的逻辑门类型: {gate_type}")

        return gate_creators[gate_type]()

    # 各个逻辑门的创建方法
    def _create_nand_gate(self) -> callable:
        from .gates import secure_nand
        return lambda a, b: secure_nand(self._keypair[1], a, b)

    def _create_and_gate(self) -> callable:
        from .gates import secure_and
        return lambda a, b: secure_and(self._keypair[1], a, b)

    def _create_or_gate(self) -> callable:
        from .gates import secure_or
        return lambda a, b: secure_or(self._keypair[1], a, b)

    def _create_xor_gate(self) -> callable:
        from .gates import secure_xor
        return lambda a, b: secure_xor(self._keypair[1], a, b)

    def _create_not_gate(self) -> callable:
        from .gates import secure_not
        return lambda a: secure_not(a)

    def _create_mux_gate(self) -> callable:
        from .gates import secure_mux
        return lambda sel, a, b: secure_mux(self._keypair[1], sel, a, b)

    def _create_nor_gate(self) -> callable:
        from .gates import secure_nor
        return lambda a, b: secure_nor(self._keypair[1], a, b)

    def _create_xnor_gate(self) -> callable:
        from .gates import secure_xnor
        return lambda a, b: secure_xnor(self._keypair[1], a, b)

    def _get_parameters_for_security(self, security_level: SecurityLevel) -> Any:
        """根据安全级别获取参数 - 基于原有TFHEParameters"""
        from .internal.keys import TFHEParameters

        # 这里可以根据安全级别调整参数
        # 目前使用默认参数，实际中可以扩展
        return TFHEParameters()

    def _add_operation_history(self, ciphertext: Any, operation: str) -> Any:
        """为密文添加操作历史"""
        if not hasattr(ciphertext, 'operation_history'):
            ciphertext.operation_history = []
        ciphertext.operation_history.append(operation)
        return ciphertext

    def _ensure_initialized(self):
        """确保引擎已初始化"""
        if self._keypair is None:
            raise TFHEError("TFHE引擎未初始化，请先调用generate_keypair()")


# 简化API函数 - 保持功能完整
def generate_keypair(security_level: SecurityLevel = SecurityLevel.STANDARD_128) -> TFHEKeyPair:
    """快速生成密钥对"""
    engine = TFHEAgentEngine()
    return engine.generate_keypair(security_level)

def encrypt_boolean(keypair: TFHEKeyPair, value: bool) -> EncryptedBit:
    """快速加密布尔值"""
    engine = TFHEAgentEngine()
    engine._keypair = keypair  # pylint: disable=protected-access
    return engine.encrypt_boolean(value)

def decrypt_boolean(keypair: TFHEKeyPair, ciphertext: EncryptedBit) -> bool:
    """快速解密密文"""
    engine = TFHEAgentEngine()
    engine._keypair = keypair  # pylint: disable=protected-access
    return engine.decrypt_boolean(ciphertext)

def create_secure_gate(keypair: TFHEKeyPair, gate_type: GateType) -> callable:
    """快速创建安全逻辑门"""
    engine = TFHEAgentEngine()
    engine._keypair = keypair  # pylint: disable=protected-access
    return engine.create_secure_gate(gate_type)