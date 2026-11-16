from copy import deepcopy

BASE = {
    "valid": True,
    "validation_method": ["MOBILEMETHOD"],
    "pin": "00000000000001",
    "user_id": "synthetic.verified",
    "full_name": "Testov Sinov Test o‘g‘li",
    "pport_no": "TEST000001",
    "birth_date": "1990-01-01",
    "sur_name": "Testov",
    "first_name": "Sinov",
    "mid_name": "Test o‘g‘li",
    "user_type": "I",
    "ret_cd": "0",
    "auth_method": "LOGINPASSMETHOD",
}


def fixtures() -> dict[str, dict]:
    result = {}
    variants = {
        "verified": {},
        "unverified": {"valid": False, "validation_method": []},
        "string-true": {"valid": "true"},
        "string-false": {"valid": "false", "validation_method": []},
        "missing-pin": {"pin": None},
        "invalid-pin": {"pin": "not-a-pin"},
        "no-middle": {"mid_name": ""},
        "legacy-date": {"birth_date": "19900101"},
        "denied": {"ret_cd": "1"},
        "mobile": {"auth_method": "MOBILEMETHOD"},
        "pkcs": {"auth_method": "PKCSMETHOD", "validation_method": ["PKCSMETHOD"]},
        "qr": {"auth_method": "QR"},
        "legal": {
            "user_type": "L",
            "auth_method": "LEPKCSMETHOD",
            "pkcs_legal_tin": "000000001",
            "validation_method": ["PKCSMETHOD"],
            "legal_info": [
                {
                    "is_basic": True,
                    "tin": "000000001",
                    "le_tin": "000000001",
                    "acron_UZ": "Testing ID test tashkiloti",
                    "le_name": "Test tashkiloti",
                }
            ],
        },
        "disabled": {},
    }
    for number, (name, changes) in enumerate(variants.items(), 1):
        profile = {**deepcopy(BASE), "pin": f"{number:014d}", "user_id": f"synthetic.{name}"}
        profile.update(deepcopy(changes))
        if profile.get("pin") is None:
            del profile["pin"]
        result[name] = profile
    return result
