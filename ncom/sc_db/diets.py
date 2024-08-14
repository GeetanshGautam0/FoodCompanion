from typing import Dict, Any


def get_diet_name(diet_order_id: int) -> str:
    return 'REGULAR'


def get_meal_options(diet_order_id: int) -> Dict[str, Any]:
    return {}


def legacy_mo_format(diet: Dict[str, Any]) -> Dict[str, Any]:
    return {}
