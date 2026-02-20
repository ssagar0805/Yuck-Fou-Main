"""
Diagnostic script — run from backend/ directory:
    python diagnose_vertex.py
"""
import os
import sys

# Step 1: Load .env manually
print("=" * 60)
print("STEP 1: Loading .env file")
try:
    from dotenv import load_dotenv
    loaded = load_dotenv(".env", override=True)
    print(f"  .env loaded: {loaded}")
except ImportError:
    # pydantic-settings uses its own loader; try manual parse
    env_path = ".env"
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())
        print("  .env parsed manually")
    else:
        print("  .env NOT FOUND!")

# Step 2: Check env vars
print()
print("=" * 60)
print("STEP 2: Environment variables")
project = os.environ.get("VERTEX_AI_PROJECT", "NOT SET")
location = os.environ.get("VERTEX_AI_LOCATION", "NOT SET")
model    = os.environ.get("VERTEX_AI_MODEL", "NOT SET")
creds    = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "NOT SET")

print(f"  VERTEX_AI_PROJECT  : {project}")
print(f"  VERTEX_AI_LOCATION : {location}")
print(f"  VERTEX_AI_MODEL    : {model}")
print(f"  GOOGLE_APPLICATION_CREDENTIALS: {creds}")

if creds != "NOT SET":
    abs_path = os.path.abspath(creds)
    exists = os.path.exists(abs_path)
    print(f"  Credentials abs path: {abs_path}")
    print(f"  Credentials file exists: {exists}")
    if exists:
        import json
        try:
            with open(abs_path) as f:
                data = json.load(f)
            print(f"  Credentials type: {data.get('type', 'unknown')}")
            print(f"  Project in creds: {data.get('project_id', 'N/A')}")
        except Exception as e:
            print(f"  Could not parse credentials: {e}")
else:
    print("  WARNING: GOOGLE_APPLICATION_CREDENTIALS is NOT SET!")

# Step 3: Test imports
print()
print("=" * 60)
print("STEP 3: Testing vertexai imports")
try:
    import vertexai
    print("  vertexai import: OK")
except Exception as e:
    print(f"  vertexai import FAILED: {e}")
    sys.exit(1)

try:
    from vertexai.preview.generative_models import GenerativeModel, GenerationConfig
    print("  GenerativeModel import: OK")
except Exception as e:
    print(f"  GenerativeModel import FAILED: {e}")
    sys.exit(1)

# Step 4: Try vertexai.init()
print()
print("=" * 60)
print("STEP 4: vertexai.init()")
try:
    vertexai.init(project=project, location=location)
    print("  vertexai.init(): OK")
except Exception as e:
    print(f"  vertexai.init() FAILED: {type(e).__name__}: {e}")

# Step 5: Try a real API call
print()
print("=" * 60)
print("STEP 5: Making real Gemini API call (synchronous)")
try:
    model_client = GenerativeModel(model)
    cfg = GenerationConfig(
        response_mime_type="application/json",
        temperature=0.1,
        max_output_tokens=64,
    )
    response = model_client.generate_content(
        'Return exactly this JSON: {"found": true, "test": "hello"}',
        generation_config=cfg,
    )
    print(f"  Response: {response.text[:200]}")
    print("  SUCCESS: Gemini API call works!")
except Exception as e:
    print(f"  FAILED: {type(e).__name__}: {str(e)[:1000]}")

print()
print("=" * 60)
print("Diagnosis complete.")
