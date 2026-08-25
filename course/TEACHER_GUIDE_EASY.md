# bobbypin - Simple Teacher's Guide (GUI edition)

Same lessons as TEACHER_GUIDE.md, taught entirely in the browser tool.
No JSON commands. Students click buttons.

---

## What you are teaching

A program has a check inside it: "is this license key good?"
Students find that check using the tool's Patch Console,
click one button to disable it in a COPY of the file,
and prove the copy now always says yes.

The original file is never modified. The browser downloads
a separate `_patched.exe` copy every time.

---

## Word list

| Word | Meaning |
|---|---|
| binary / .exe | the program file |
| string | text stored inside the file, like "License invalid" |
| offset | the exact position of something inside the file, written in hex |
| candidate card | a card in the Patch Console showing one real jump the tool found |
| FAIL / OK badge | whether the card sits near a failure message or a success message |
| String Ref | where the code reads that text from |
| Branch Offset | the exact position of the jump instruction itself |
| NOP | the CPU's "do nothing" instruction; clicking erases the jump |
| flip | swap the jump's condition (74 becomes 75, and back) |

---

## Before class

```bash
python3 -m pip install capstone      # usually already installed
```

Start the tool:

```bash
python3 ~/Documents/bobbypin/bobbypin_gui.py
```

Open http://127.0.0.1:8877 in the browser. You should see
"Select or Drag Target Binary".

Optional for testing results in class:

```bash
brew install --cask wine-stable      # runs Windows .exe on macOS
```

Start every class with the rule:
we treat every program we work on as our own — the person running the app is the owner of the target file.

Show the **Workflow** button (top right) once. It lists the same nine
steps this course teaches. The course IS that workflow, practiced.

---

## Module 1 - One check (do this together)

Files: `course/module1/crackme.exe`

### Step 1: Baseline first

Put `crackme.exe` in its own folder. Run it once (with wine, or any
Windows machine) and type a wrong key. Write down the exact failure
text: "License invalid. Please purchase a key."

### Step 2: Drop it in

Drag `crackme.exe` onto the browser page. The Overview tab appears.
Point out: PE32+, no .NET warning, no packer warning = we may continue.

### Step 3: Read the Patch Console

Open the **Patch Console** tab. Three cards appear. Read each card aloud:
the quoted text, the FAIL/OK badge, the Branch Offset.

Two cards quote compiler-tool messages ("Mingw-w64 runtime failure",
"VirtualProtect failed"). Skip those forever - they are not part of
the program's logic.

One real card remains. That is our suspect.

### Step 4: Try the card

Click **NOP Jump (0x90)** on that card. The browser downloads
`crackme_patched.exe` (look in Downloads). Run it with a wrong key.

| Tried | Result with wrong key | Conclusion |
|---|---|---|
| NOP on the app card (Branch Offset `0xb26`) | "Access granted" | this was the real check |

Answer key for module 1: the winning card is Candidate #1
(Branch Offset `0xb26`). One click, done.

If a future target ever shows more than one non-compiler card, use the
ladder below and change ONE thing before every test.

### Step 5: If NOP had not worked

The rule ladder: NOP the card, test; if nothing changed, **Flip** the
same card, test again; if still nothing, move to the next card.
Change ONE thing before every test.

### Prove it

Run both files with a wrong key:

```bash
wine crackme.exe <<< "banana"            # invalid
wine crackme_patched.exe <<< "banana"    # granted
```

---

## Module 2 - Two checks in a row (students try)

Files: `course/module2/crackme2.exe`

Students repeat Module 1 alone: drop, read cards, NOP, test.

This time the Patch Console shows TWO real cards (plus the compiler
ones to skip):

- Candidate #1 - Branch Offset `0xb66`
- Candidate #2 - Branch Offset `0xb76`, quoting
  "Account suspended. Contact support."

Step 1: NOP Candidate #1, test with a short garbage key.
The password lock is gone - but now the program answers
"Account suspended. Contact support." instead of "Access granted".

The big lesson: **real software has more than one lock.**
Removing the first lock revealed a second one.

Step 2: NOP Candidate #2 (the card quoting "Account suspended"),
test again with garbage.

Now any input - even "banana" - gets "Access granted".
Both locks opened with two button clicks, entirely in the browser.

Rule that still applies: change ONE thing, then test.
Never click both cards before running the program once.

For comparison, finished copies ship in the folder:
`crackme2_patched.exe` (first lock only) and
`crackme2_full.exe` (both locks opened).

Mention the **Frida Monitor** tab here: when a tool cannot see a check,
watching the program live often reveals it.

---

## Module 3 - No failure message (students work alone)

Files: `course/module3/crackme3.exe`

This program fails silently: wrong key, no message, program exits.
Nothing to search for on the failure side.

Student method:

1. Baseline: run it, wrong key, observe: nothing happens. Also true:
   exit code 3 (`echo $?` shows 3).
2. Open **String Inspector**, filter: `Welcome`.
   Found: "Welcome back, licensed user." - the success message.
3. Back to **Patch Console**: no card quotes that success text.
   Try the remaining non-compiler FAIL cards, one at a time,
   NOP then test, following the Module 1 ladder.

Answer key: Candidate #1, Branch Offset `0xb26`, NOP. After that,
ANY key prints "Welcome back, licensed user." and exits cleanly.

---

## Rules to repeat every class

1. You are the owner of the target file — treat every program you work on as your own.
2. The original file stays untouched; patches download as copies.
3. Change one thing, then test. Never two things at once.
4. The ladder: NOP, test, Flip, test, next card.
5. Skip cards quoting compiler or library messages forever.
6. A card quoting the right text can still be the wrong card.
   Testing decides.

---

## Quiz ideas

- Show two cards from a fresh analysis. Ask: which do you try first,
  and why?
- Show Module 2's "Account suspended" moment. Ask what it proves
  about the program's insides.
- Ask why a card can quote the failure message and still be useless.
- Ask what NOP means to the processor, and why erasing a jump can
  change which message appears.
