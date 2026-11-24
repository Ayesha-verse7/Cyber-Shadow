
from flask import Flask, render_template, request, jsonify

from cyber_shadow import policy, hashing, storage, cracker

app = Flask(__name__)
print("STATIC FOLDER:", app.static_folder)
last_crack_result = None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/policy", methods=["POST"])
def check_policy():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Please enter a test password."}), 400

    result = policy.check_password_policy(password)

    return jsonify({
        "valid": result.is_valid,
        "score": result.score,
        "rating": result.rating,
        "report": policy.format_policy_report(result)
    })


@app.route("/api/hash", methods=["POST"])
def generate_password_hash():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Please enter a test password."}), 400

    hashes = hashing.generate_all_hashes(password)

    return jsonify({
        "md5": hashes["md5"],
        "sha1": hashes["sha1"]
    })


@app.route("/api/save-hash", methods=["POST"])
def save_test_hash():
    data = request.get_json(silent=True) or {}

    password = data.get("password", "")
    algorithm = data.get("algorithm", "sha1").lower()
    label = data.get("label", "web-test")

    if not password:
        return jsonify({"error": "Enter a test password."}), 400

    if algorithm not in hashing.SUPPORTED_ALGORITHMS:
        return jsonify({"error": "Unsupported algorithm."}), 400

    digest = hashing.generate_hash(password, algorithm)

    record = storage.add_hash_record(
        label=label,
        algorithm=algorithm,
        digest=digest,
        plaintext_length=len(password)
    )

    return jsonify({
        "message": "Test hash saved successfully.",
        "record": record
    })


@app.route("/api/hashes", methods=["GET"])
def get_saved_hashes():
    records = storage.load_hashes()
    return jsonify(records)


@app.route("/api/crack", methods=["POST"])
def run_dictionary_demo():
    global last_crack_result

    data = request.get_json(silent=True) or {}
    label = data.get("label")

    records = storage.load_hashes()
    record = next(
        (item for item in records if item.get("label") == label),
        None
    )

    if record is None:
        return jsonify({"error": "Saved test hash not found."}), 404

    result = cracker.crack_hash(
        target_hash=record["hash"],
        algorithm=record["algorithm"]
    )

    last_crack_result = result

    return jsonify({
        "report": cracker.format_crack_report(result),
        "found": result.found,
        "attempts": result.attempts,
        "elapsed_seconds": result.elapsed_seconds
    })


@app.route("/api/stats", methods=["GET"])
def get_statistics():
    if last_crack_result is None:
        return jsonify({"message": "No dictionary test has been run yet."})

    return jsonify({
        "attempts": last_crack_result.attempts,
        "total_candidates": last_crack_result.total_candidates,
        "elapsed_seconds": last_crack_result.elapsed_seconds,
        "attempts_per_second": last_crack_result.attempts_per_second,
        "found": last_crack_result.found
    })


if __name__ == "__main__":
    app.run(debug=False)