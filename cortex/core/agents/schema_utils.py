"""Schema conversion utilities for agent operations.

This module is part of CoreSight, a lightweight and transparent micro-framework for orchestrating
LLM-based agents. CoreSight was created by Petru Arakiss (petruarakiss@gmail.com) and is used
under private license.

This is a forked version specifically modified for the Cortex POC project.

This module provides utilities for converting Python functions and their type hints into JSON schema
representations that can be used by LLM models for function calling.
"""

from inspect import signature, _empty
from typing import Any, Callable, Dict, Optional, get_type_hints, TypedDict, List, Type


class ParameterSchema(TypedDict):
    """Schema definition for a function parameter.

    Attributes:
        type: JSON schema type of the parameter
        description: Optional description of the parameter's purpose
    """

    type: str
    description: Optional[str]


class FunctionSchema(TypedDict):
    """Schema definition for a function.

    Attributes:
        type: Always "function" for function schemas
        function: Dictionary containing function metadata and parameters
    """

    type: str
    function: Dict[str, Any]


def map_python_to_json_type(python_type: Type[Any]) -> str:
    """Map Python types to JSON schema types.

    Args:
        python_type: Python type annotation to convert

    Returns:
        str: Corresponding JSON schema type string
    """
    type_mapping = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
        type(None): "null",
    }
    return type_mapping.get(python_type, "string")


def create_parameter_definition(param_name: str, param_type: str) -> ParameterSchema:
    """Create a parameter schema definition.

    Args:
        param_name: Name of the parameter
        param_type: JSON schema type for the parameter

    Returns:
        ParameterSchema: Parameter schema definition
    """
    return ParameterSchema(type=param_type, description=None)


def get_required_parameters(func_signature: signature) -> List[str]:
    """Extract required parameters from a function signature.

    Args:
        func_signature: Function signature to analyze

    Returns:
        List[str]: List of required parameter names
    """
    return [param.name for param in func_signature.parameters.values() if param.default == _empty]


def convert_function_to_schema(func: Callable[..., Any]) -> FunctionSchema:
    """Convert a Python function to a JSON schema definition.

    This function analyzes a Python function's signature, type hints, and docstring
    to create a JSON schema representation that can be used by LLM models.

    Args:
        func: Function to convert to schema

    Returns:
        FunctionSchema: JSON schema representation of the function

    Raises:
        ValueError: If function signature cannot be parsed
        KeyError: If type annotation is invalid
    """
    try:
        func_signature = signature(func)
        type_annotations = get_type_hints(func)

        parameters = {
            name: create_parameter_definition(
                name, map_python_to_json_type(type_annotations.get(name, str))
            )
            for name in func_signature.parameters
        }

        required_params = get_required_parameters(func_signature)

        return FunctionSchema(
            type="function",
            function={
                "name": func.__name__,
                "description": func.__doc__ or "",
                "parameters": {
                    "type": "object",
                    "properties": parameters,
                    "required": required_params,
                },
            },
        )
    except ValueError as e:
        raise ValueError(f"Failed to parse signature of function {func.__name__}: {str(e)}")
    except KeyError as e:
        raise KeyError(f"Invalid type annotation in function {func.__name__}: {str(e)}")
