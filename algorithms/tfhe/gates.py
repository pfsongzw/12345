"""
同态逻辑门操作 - 基于原有boot_gates.py的Agent友好包装器
"""

from typing import Union, cast
import numpy as np
from numpy.typing import NDArray

from .types import GateType, OperationResult
from .internal.boot_gates import (
    NAND, AND, OR, XOR, NOT, MUX, CONSTANT,
    NOR, XNOR, ANDNY, ANDYN, ORNY, ORYN
)
from .internal.keys import empty_ciphertext


# 语义化函数 - 包装原有逻辑门功能
def secure_nand(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全NAND门: not(a and b) - 基于原有NAND函数"""
    result = create_empty_ciphertext_like(a)
    NAND(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_nand")


def secure_and(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全AND门: a and b - 基于原有AND函数"""
    result = create_empty_ciphertext_like(a)
    AND(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_and")


def secure_or(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全OR门: a or b - 基于原有OR函数"""
    result = create_empty_ciphertext_like(a)
    OR(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_or")


def secure_xor(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全XOR门: a xor b - 基于原有XOR函数"""
    result = create_empty_ciphertext_like(a)
    XOR(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_xor")


def secure_not(ciphertext: Any) -> Any:
    """安全NOT门: not a - 基于原有NOT函数"""
    result = create_empty_ciphertext_like(ciphertext)
    NOT(result, ciphertext)
    return _add_operation_history(result, "secure_not")


def secure_mux(cloud_key: Any, select: Any, a: Any, b: Any) -> Any:
    """安全MUX门: select ? a : b - 基于原有MUX函数"""
    result = create_empty_ciphertext_like(a)
    MUX(cloud_key, result, select, a, b)
    return _add_operation_history(result, "secure_mux")


def secure_constant(value: Union[bool, NDArray[np.int32]]) -> Any:
    """安全常数门: 创建常数密文 - 基于原有CONSTANT函数"""
    result = create_empty_ciphertext_for_constant(value)
    CONSTANT(result, value)
    return _add_operation_history(result, f"secure_constant({value})")


def secure_nor(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全NOR门: not(a or b) - 基于原有NOR函数"""
    result = create_empty_ciphertext_like(a)
    NOR(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_nor")


def secure_xnor(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全XNOR门: not(a xor b) - 基于原有XNOR函数"""
    result = create_empty_ciphertext_like(a)
    XNOR(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_xnor")


def secure_andny(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全ANDNY门: not(a) and b - 基于原有ANDNY函数"""
    result = create_empty_ciphertext_like(a)
    ANDNY(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_andny")


def secure_oryn(cloud_key: Any, a: Any, b: Any) -> Any:
    """安全ORYN门: a or not(b) - 基于原有ORYN函数"""
    result = create_empty_ciphertext_like(a)
    ORYN(cloud_key, result, a, b)
    return _add_operation_history(result, "secure_oryn")


class SecureGates:
    """安全逻辑门操作类 - 统一管理所有逻辑门"""

    def __init__(self, cloud_key: Any):
        self.cloud_key = cloud_key

    def execute_gate_operation(
        self,
        gate_type: GateType,
        *inputs: Any
    ) -> OperationResult:
        """执行逻辑门操作 - 统一入口点"""
        try:
            gate_operations = {
                GateType.NAND: secure_nand,
                GateType.AND: secure_and,
                GateType.OR: secure_or,
                GateType.XOR: secure_xor,
                GateType.NOT: secure_not,
                GateType.MUX: secure_mux,
                GateType.NOR: secure_nor,
                GateType.XNOR: secure_xnor
            }

            if gate_type not in gate_operations:
                return OperationResult(
                    success=False,
                    result=None,
                    message=f"不支持的逻辑门类型: {gate_type}"
                )

            # 调用相应的逻辑门函数
            result = gate_operations[gate_type](self.cloud_key, *inputs)

            return OperationResult(
                success=True,
                result=result,
                message=f"{gate_type.value} 门操作成功",
                metadata={'gate_type': gate_type.value}
            )

        except Exception as e:
            return OperationResult(
                success=False,
                result=None,
                message=f"逻辑门操作失败: {str(e)}",
                metadata={'gate_type': gate_type.value}
            )


# 工具函数
def create_empty_ciphertext_like(sample: Any) -> Any:
    """创建与给定样本相同形状的空密文 - 基于原有empty_ciphertext"""
    from .internal.keys import tfhe_parameters
    params = tfhe_parameters(sample) if hasattr(sample, 'params') else None
    if params is None:
        # 回退方案
        params = getattr(sample, 'params', None)

    if params is not None:
        return empty_ciphertext(params, sample.shape)
    else:
        # 如果无法获取参数，创建默认形状的密文
        return empty_ciphertext(None, sample.shape)


def create_empty_ciphertext_for_constant(value: Union[bool, NDArray[np.int32]]) -> Any:
    """为常数创建空密文"""
    from .internal.keys import TFHEParameters, empty_ciphertext
    params = TFHEParameters()
    shape = (1,) if isinstance(value, bool) else value.shape
    return empty_ciphertext(params, shape)


def _add_operation_history(ciphertext: Any, operation: str) -> Any:
    """为密文添加操作历史"""
    if not hasattr(ciphertext, 'operation_history'):
        ciphertext.operation_history = []
    ciphertext.operation_history.append(operation)
    return ciphertext