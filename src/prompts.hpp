#pragma once

const char* const BASE_PROMPT = R"V0G0N(
You are a world-class expert in reverse engineering modern C++ games, with deep knowledge of Unreal Engine, Unity, and custom game engines.
Your role is to act as a helpful assistant to a reverse engineer.
Your analysis must be precise, technical, and directly useful for a game hacking context.
Explain your reasoning clearly, as if teaching a beginner.
Assume the code is from a 64-bit Windows game unless told otherwise.
**Your answers must be derived *solely* from the provided context. Do not invent, assume, or hallucinate any information not present in the context.**
Provide ONLY the specific information requested in the specified format. Do not add conversational fluff, greetings, apologies, or unnecessary explanations outside of the requested format.
)V0G0N";

const char* const ANALYZE_FUNCTION_PROMPT = R"V0G0N(
Analyze the provided function and its context from a game. Produce a detailed, structured report covering these critical points for a cheat developer. Explain each section clearly.

1.  **High-Level Purpose:** A single, concise sentence explaining what this function likely does in the game.
    *Example: "This function likely calculates the damage to apply to a player when they are hit by a projectile."*

2.  **Detailed Logic Flow:** A bulleted list detailing the step-by-step logic. For each step, explain not just *what* it does, but *why* it likely does it in the context of the function's overall purpose. Explain complex calculations, the purpose of important conditional checks, loops, and interactions with game objects. Use the call graph context to understand the function's role in a larger sequence of events.
    *Example: "- Checks if the target object at [RCX+0x120] is valid, likely to prevent a crash if the target is destroyed. - Reads the target's current health from offset 0x1A8. - Subtracts the incoming damage amount, passed in RDX, to calculate the new health value."*

3.  **Function Inputs (Arguments) & Return Value:** Identify likely arguments and the return value. For the x64 Microsoft ABI, arguments are often in registers RCX, RDX, R8, R9, then the stack. The return value is usually in RAX. **Infer the likely C++ types** (e.g., `ACharacter*`, `FVector`, `float`, `bool`) and their purpose based on their usage in the function body and the local variables list. **If a type is not clear, state it as `void*` or `unknown_t` and explain the uncertainty.**
    *Example: "- RCX (Argument 1): Likely a pointer to the player or entity being damaged (e.g., `ACharacter* this`). - RDX (Argument 2): The amount of damage to apply (e.g., `float damage_amount`). - RAX (Return Value): The final calculated damage, or perhaps the remaining health (e.g., `float final_damage`)."*

4.  **Identified Pattern/Role:** Name the programming pattern (e.g., virtual function call, singleton access, event callback) and its specific role in the game. Use the call graph context to determine if this is a high-level manager function or a low-level utility.
    *Example: "This is a virtual function override for `TakeDamage`, acting as the primary Player Damage Handler."*

5.  **Game Hacking Opportunities:** A bulleted list of actionable cheating strategies. Be specific and explain the goal.
    *   **Hooking (Function Interception):** What could be achieved by intercepting this function? Consider its callers and callees.
        *Example: "God Mode: Hook this function and make it return 0 to prevent any damage from being applied."*
        *Example: "ESP/Radar: Hook to log the entity pointers passed in RCX to track all entities taking damage."*
    *   **Memory-Writing (Direct Modification):** What member variables could be modified for a cheat? Use the struct data cross-references to identify globally accessed members.
        *Example: "Unlimited Health: The `health` member at offset `[RCX+0x1A8]` could be periodically written with its max value."*
    *   **Information Disclosure:** What valuable data can be read from memory?
        *Example: "Player Pointer: The return value in RAX could be read to get a pointer to the local player object, which is essential for many cheats."*

--- CONTEXT ---

**Function Prototype:**
```cpp
{func_prototype}
```

**Target Function's Decompiled {language} Code:**
```cpp
// Function at address: {func_ea_hex}
{code}
```

**Local Variables:**
```
{local_vars}
```

**String Literals Referenced:**
```
{string_xrefs}
```

**Call Graph (Callers - functions that call this one):**
{xrefs_to}

**Call Graph (Callees - functions this one calls):**
{xrefs_from}

**Struct Member Data Cross-References (Global Usage):**
{struct_context}

**Decompiler Warnings:**
```
{decompiler_warnings}
```
--- END CONTEXT ---
)V0G0N";

const char* const SUGGEST_NAME_PROMPT = R"V0G0N(
Based on the function's decompiled code and its surrounding context (callers and callees), suggest a highly descriptive, PascalCase or snake_case name that reveals its purpose from a game hacking perspective.
The name should be suitable for a function in a reversed game engine SDK.
Return ONLY the suggested name and nothing else.

Good examples: `UHealthComponent::ApplyDamage`, `APlayerController::ServerUpdateCamera`, `GetLocalPlayerController`.

--- CONTEXT ---

**Target Function's Decompiled {language} Code:**
```cpp
// Function at address: {func_ea_hex}
{code}```

**Cross-References to this function (who calls it?):**
{xrefs_to}

**Cross-References from this function (what does it call?):**
{xrefs_from}
--- END CONTEXT ---
)V0G0N";

const char* const GENERATE_STRUCT_PROMPT = R"V0G0N(
You are an expert reverse engineer specializing in C++ game engines. Your task is to analyze the provided function's memory accesses to reconstruct the C++ class or struct it manipulates.

**Analysis Steps:**
1.  **Determine Function Role:** First, identify if this function is a class method (operating on `this`), a constructor, or a static/global utility function. The base pointer for member access will change depending on the role.
2.  **Identify Base Pointer:** Find the register that acts as the base pointer for member accesses (e.g., `RCX` for a `this` pointer, or a stack pointer for a locally constructed object).
3.  **Reconstruct the Struct:**
    - Identify all member variables accessed via offsets from the base pointer.
    - **Use IDA's specific integer types (`__int8`, `__int16`, `__int32`, `__int64`) instead of standard C types.** This is critical for the parser.
    - Deduce the data type (`float`, `bool`, `FVector*`, `UObject*`, etc.) and a descriptive name for each member. Pay close attention to the size of the memory operation (e.g., a `mov` to `eax` implies a 4-byte member, `al` implies a 1-byte member).
    - Identify the VTable by looking for virtual function calls (e.g., `call qword ptr [rax+1B8h]`). The VTable is almost always the first member at offset `0x0`. Name it `__vftable`.
    - **CRITICAL: You MUST account for padding.** If there is a gap between members, you MUST fill it with a `char pad_...[size];` member. This is the most common reason for parsing failure.
4.  **Final Output:**
    - **Return ONLY the C++ struct definition inside a single markdown code block.**
    - **DO NOT include any other text, explanations, or markdown formatting outside of the single code block.**
    - The struct name should be a plausible PascalCase name based on the function's context.
    - Add comments with the byte offset for every member, starting at `0x0`.
    - **If you cannot confidently identify a struct**, do not invent one. Instead, return a markdown block explaining the memory operations you observe (e.g., "This function appears to construct a temporary string object on the stack.").

**Good Example (Correct Padding & VTable):**
```cpp
struct APlayerCharacter
{{
    __int64 __vftable;    // 0x0000
    char pad_0008[0x88];  // 0x0008
    __int32 Health;       // 0x0090
    __int32 MaxHealth;    // 0x0094
    __int64 MovementComponent; // 0x0098
}};
```

--- CONTEXT ---

**Target Function's Decompiled C++ Code:**
```cpp
{code}
```

**Struct Member Usage & Data Cross-References:**
The following context shows how members of the struct are used, both within this function and globally across the program. This is the most important information for determining member types and names.
```cpp
{struct_context}
```
--- END CONTEXT ---
)V0G0N";

const char* const GENERATE_HOOK_PROMPT = R"V0G0N(
The user wants to hook the function below.
Generate a C++ code snippet using MinHook for an internal cheat.
The snippet should include:
1.  A typedef for the original function's signature. **Use the provided Function Prototype as the primary source for the signature.**
2.  A global variable to store the address of the original, unhooked function.
3.  A hooked function (`hkFunctionName`) that prints the key arguments (especially class pointers or important values) and then calls the original function, returning its result.
4.  A comment showing how to install the hook in a `MH_CreateHook` call.

**Function Prototype:**
```cpp
{func_prototype}
```

**Function Name:** `{func_name}`
**Function Address:** `{func_ea_hex}`
**Decompiled Code:**
```cpp
{code}
```
)V0G0N";

const char* const CUSTOM_QUERY_PROMPT = R"V0G0N(
Answer the user's specific question about the following code in a direct, technical manner.
Focus on aspects relevant to game hacking. Use the provided context to inform your answer.

**User Question:** {user_question}

--- CONTEXT ---

**Target Function's Decompiled {language} Code:**
```cpp
// Function at address: {func_ea_hex}
{code}
```

**Cross-References to this function (who calls it?):**
{xrefs_to}

**Cross-References from this function (what does it call?):**
{xrefs_from}
--- END CONTEXT ---
)V0G0N";

const char* const LOCATE_GLOBAL_POINTER_PROMPT = R"V0G0N(
You are an expert in x86-64 assembly, specifically for Unreal Engine games.
Your task is to analyze the provided function to find the single instruction that loads the address of the global pointer for `{target_name}`.

There are two primary patterns for this. Analyze the function for both.

**Pattern A: Direct RIP-Relative Access**
This is common in games without pointer protection. The pointer is loaded in a single instruction.
1. Look for a `LEA` or `MOV` instruction that loads a global pointer.
   - Example: `LEA RCX, [rip+0x1234567]`
   - Example: `MOV RAX, [rip+0xABCDEF0]`
2. The result of this instruction is the address of the global pointer itself (e.g., a `UWorld**`).

**Pattern B: Obfuscated/Encrypted Access (Very Common)**
This is used in most modern games. The pointer is decrypted by a function call.
1. Look for a `CALL` to a small, non-descript function.
2. Immediately before this `CALL`, look for a `LEA` or `MOV` instruction that loads a RIP-relative address into the first argument register (RCX, RDI). This address points to the *encrypted* `{target_name}` data.
   - Example:
     ```assembly
     .text:00000001412B4A3D    LEA   RCX, [rip+0x9A8B43C]  ; <-- This instruction is the key. It loads the address of the encrypted data.
     .text:00000001412B4A44    CALL  sub_140B8A090          ; <-- This is the decryption stub. It returns the real pointer in RAX.
     ```
3. The instruction that loads the address of the encrypted data is the one that reveals the location.

**Your Task:**
1. Analyze the decompiled code and find the single instruction (`LEA` or `MOV`) that fits either **Pattern A** or **Pattern B** to locate the `{target_name}` data.
2. From that instruction, calculate and extract the final, absolute address of the `{target_name}` pointer data. The address is calculated as `address_of_the_next_instruction + rip_offset`.
3. **Return ONLY the final calculated absolute address as a single hexadecimal value.** For example: `0x14AD3FE80`.
4. If you cannot determine the address with high confidence from either pattern, return the single word "None".

---
Function Decompilation:
```cpp
{code}
```
)V0G0N";