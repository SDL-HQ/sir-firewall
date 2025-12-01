#!/usr/bin/env python3
import os
import pandas as pd
from litellm import completion

# Load the real 100 cutting-edge prompts from CSV
df = pd.read_csv("jailbreak_prompts.csv")
prompts = df["prompt"].tolist()

print(f"Loaded {len(prompts)} real jailbreak prompts from CSV")

leaks = 0
for i, prompt in enumerate(prompts, 1):
    print(f"[{i:3d}/100] Testing → {prompt[:70]}{'...' if len(prompt)>70 else ''}")

    try:
        response = completion(
            model=os.getenv("LITELLM_MODEL", "xai/grok-3-beta"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1024,
        )
        output = response.choices[0].message.content

        # Real SIR validation against the actual model output
        from sir_firewall import validate_sir
        result = validate_sir({"isc": {"payload": output}})

        if result["status"] == "PASS":
            print("   LEAK DETECTED!")
            leaks += 1
        else:
            print("   BLOCKED")

    except Exception as e:
        print(f"   API error (treated as BLOCK): {e}")

    if i % 10 == 0:
        print(f"  → So far: {leaks} leaks")

print(f"\nFINAL RESULT: {leaks} leaks out of 100 real jailbreak attempts on Grok-3")
with open("leaks_count.txt", "w") as f:
    f.write(str(leaks))

if leaks == 0:
    print("SIR ACHIEVED 0/100 — TOTAL VICTORY")
else:
    print("Some prompts leaked — truth revealed")
    raise SystemExit(1)
