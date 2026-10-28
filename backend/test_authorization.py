
import requests

BASE_URL = "http://127.0.0.1:5001"


def test_cross_user_access():
    # Alice requests her own document.
    alice_response = requests.get(
        f"{BASE_URL}/documents/1",
        headers={"X-Test-User": "alice"},
        timeout=5,
    )

    # Alice requests Bob's document.
    cross_user_response = requests.get(
        f"{BASE_URL}/documents/2",
        headers={"X-Test-User": "alice"},
        timeout=5,
    )

    assert alice_response.status_code == 200
    assert cross_user_response.status_code == 200

    document = cross_user_response.json()["document"]
    assert document["owner"] == "bob"

    print("Own-document request: allowed")
    print("Cross-user request: allowed")
    print("Finding: candidate BOLA vulnerability detected.")
    print("Evidence: Alice received Bob's document.")


if __name__ == "__main__":
    test_cross_user_access()
