"""
TFHE (Fully Homomorphic Encryption) Library
重构版本 - 保持原有功能完整性的Agent友好接口

主要模块：
- core: 核心加密功能 (保持原有keys.py, lwe.py等功能)
- gates: 同态逻辑门操作 (保持原有boot_gates.py功能) 
- types: 数据类型定义和Agent友好接口
- utils: 工具函数
- internal: 内部实现 (保持原有所有底层文件)
"""

# 导出原有所有功能，保持向后兼容
from .internal.lwe import *  # noqa: F401, F403
from .internal.lwe_bootstrapping import *  # noqa: F401, F403
from .internal.keys import *  # noqa: F401, F403
from .internal.numeric_functions import *  # noqa: F401, F403
from .internal.tlwe import *  # noqa: F401, F403
from .internal.polynomials import *  # noqa: F401, F403
from .internal.tgsw import *  # noqa: F401, F403
from .internal.boot_gates import *  # noqa: F401, F403
from .internal.utils import *  # noqa: F401, F403

# Agent友好接口
from .core import (
    TFHEAgentEngine,
    generate_keypair,
    encrypt_boolean,
    decrypt_boolean,
    create_secure_gate
)
from .gates import (
    secure_nand, secure_and, secure_or, secure_xor,
    secure_not, secure_mux, secure_constant,
    secure_nor, secure_xnor, secure_andny, secure_oryn
)
from .types import SecurityLevel, GateType, SecurityConfig, CiphertextInfo

__all__ = [
    # 核心功能 - Agent友好
    'TFHEAgentEngine', 'generate_keypair',
    'encrypt_boolean', 'decrypt_boolean', 'create_secure_gate',

    # 逻辑门 - Agent友好
    'secure_nand', 'secure_and', 'secure_or', 'secure_xor',
    'secure_not', 'secure_mux', 'secure_constant',
    'secure_nor', 'secure_xnor', 'secure_andny', 'secure_oryn',

    # 配置和类型
    'SecurityLevel', 'GateType', 'SecurityConfig', 'CiphertextInfo',

    # 原有功能 - 保持兼容
    'TFHEParameters', 'TFHESecretKey', 'TFHECloudKey',
    'tfhe_encrypt', 'tfhe_decrypt', 'tfhe_key_pair',
    'NAND', 'AND', 'OR', 'XOR', 'NOT', 'MUX', 'CONSTANT'
]