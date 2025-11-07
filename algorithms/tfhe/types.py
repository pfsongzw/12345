"""
TFHE类型定义 - 为Agent提供清晰的类型系统
"""

from enum import Enum
from typing import NamedTuple, Any, Dict, Tuple
from dataclasses import dataclass
import numpy as np


class SecurityLevel(Enum):
    """安全级别枚举 - 便于Agent选择"""
    BASIC_80 = 80
    STANDARD_128 = 128
    HIGH_192 = 192
    ULTRA_256 = 256


class GateType(Enum):
    """逻辑门类型枚举 - 覆盖所有原有逻辑门"""
    NAND = "nand"
    AND = "and"
    OR = "or"
    XOR = "xor"
    NOT = "not"
    MUX = "mux"
    XNOR = "xnor"
    NOR = "nor"
    ANDNY = "andny"  # not(a) and b
    ORYN = "oryn"    # a or not(b)


@dataclass
class SecurityConfig:
    """安全配置 - 集中管理参数"""
    security_level: SecurityLevel = SecurityLevel.STANDARD_128
    polynomial_degree: int = 1024
    ciphertext_modulus: int = 2**32
    enable_verbose_logging: bool = True
    use_original_parameters: bool = True  # 使用原有参数设置

    @classmethod
    def from_security_level(cls, level: SecurityLevel) -> 'SecurityConfig':
        """根据安全级别创建配置"""
        configs = {
            SecurityLevel.BASIC_80: cls(
                security_level=SecurityLevel.BASIC_80,
                polynomial_degree=512
            ),
            SecurityLevel.STANDARD_128: cls(
                security_level=SecurityLevel.STANDARD_128,
                polynomial_degree=1024
            ),
            SecurityLevel.HIGH_192: cls(
                security_level=SecurityLevel.HIGH_192,
                polynomial_degree=2048
            ),
            SecurityLevel.ULTRA_256: cls(
                security_level=SecurityLevel.ULTRA_256,
                polynomial_degree=4096
            )
        }
        return configs.get(level, cls())


@dataclass
class CiphertextInfo:
    """密文信息 - 便于Agent理解状态"""
    shape: tuple
    noise_level: float
    operations_count: int
    security_level: SecurityLevel
    health_status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'shape': self.shape,
            'noise_level': self.noise_level,
            'operations_count': self.operations_count,
            'security_level': self.security_level.value,
            'health_status': self.health_status
        }


# 类型别名 - 提高代码可读性
EncryptedBit = Any  # LWESampleArray的别名
TFHEKeyPair = Tuple[Any, Any]  # (TFHESecretKey, TFHECloudKey)的别名


class OperationResult(NamedTuple):
    """操作结果 - 标准化返回格式"""
    success: bool
    result: Any
    message: str
    metadata: Dict[str, Any] = {}