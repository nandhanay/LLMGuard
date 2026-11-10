"""
eval/datagen.py — Synthetic Dataset Generator (Faker en_IN)
============================================================

Generates controlled, annotated multi-turn conversations featuring
fictional Indian personas with known ground-truth entities, aliases,
and gradual disclosure of quasi-identifiers.

Scenarios:
  - college_academic: Student enrollment, faculty advising, grades.
  - hr_workplace: Job application, background check, salary review.
  - finance_banking: Loan application, KYC details, tax inquiry.
  - legal_administrative: Rental agreement, dispute, municipal service.

Standard Dataset JSON Schema:
  - conversation_id
  - scenario
  - dataset_source & provenance
  - ground_truth_profile
  - entities (canonical name, type, category, aliases, first_disclosed_turn)
  - turns (turn_number, user_prompt, annotations with exact character offsets)

Usage:
    python eval/datagen.py --count 10 --seed 42 --out data/synthetic/synthetic_conversations_v1.json
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from faker import Faker


# ── Identifier Categories ─────────────────────────────────────

CATEGORY_DIRECT = "DIRECT_IDENTIFIER"       # Names, emails, phone numbers, Aadhaar, PAN
CATEGORY_QUASI = "QUASI_IDENTIFIER"         # City, college, graduation year, job title
CATEGORY_SENSITIVE = "SENSITIVE_ATTRIBUTE"  # Salary, medical condition, religion
CATEGORY_NON_SENSITIVE = "NON_SENSITIVE"    # Generic conversational text


# ── Data Models ───────────────────────────────────────────────

@dataclass
class EntityAnnotation:
    """Exact character-level ground truth annotation."""
    entity_id: str
    entity_type: str
    text: str
    start: int
    end: int
    identifier_category: str


@dataclass
class EntityGroundTruth:
    """Ground truth metadata for an entity across the conversation."""
    entity_id: str
    canonical_name: str
    entity_type: str
    identifier_category: str
    aliases: list[str]
    first_disclosed_turn: int


@dataclass
class ConversationTurn:
    """A single turn in the multi-turn conversation."""
    turn_number: int
    user_prompt: str
    disclosed_entity_ids: list[str]
    annotations: list[EntityAnnotation]


@dataclass
class SyntheticConversation:
    """Complete multi-turn conversation record."""
    conversation_id: str
    scenario: str
    dataset_source: str
    license: str
    provenance: dict[str, Any]
    ground_truth_profile: dict[str, Any]
    entities: list[EntityGroundTruth]
    turns: list[ConversationTurn]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Synthetic Generator ───────────────────────────────────────

class SyntheticDatasetGenerator:
    """
    Generates synthetic Indian multi-turn conversations with controlled
    gradual disclosure and ground truth entity annotations.
    """

    def __init__(self, seed: Optional[int] = 42):
        self.seed = seed
        self.fake = Faker("en_IN")
        if seed is not None:
            self.fake.seed_instance(seed)
            random.seed(seed)

    def _generate_indian_profile(self) -> dict[str, str]:
        """Generate a realistic fictional Indian persona."""
        first_name = self.fake.first_name()
        last_name = self.fake.last_name()
        full_name = f"{first_name} {last_name}"

        # Clean sanitized email from name
        clean_first = "".join(c for c in first_name.lower() if c.isalnum())
        clean_last = "".join(c for c in last_name.lower() if c.isalnum())
        email = f"{clean_first}.{clean_last}@{self.fake.free_email_domain()}"

        # Indian mobile number format (+91 9XXXXXXXXX)
        phone = f"+91-{random.choice(['98', '97', '99', '91', '88'])}{random.randint(10000000, 99999999)}"

        # Indian PAN card format (5 letters, 4 digits, 1 letter)
        pan_letters = "".join(random.choices("ABCDE", k=3)) + "P" + random.choice("ABCDE")
        pan_digits = f"{random.randint(1000, 9999)}"
        pan_last = random.choice("A" "B" "C" "D" "E")
        pan_number = f"{pan_letters}{pan_digits}{pan_last}"

        cities = ["Bengaluru", "Chennai", "Hyderabad", "Mumbai", "Pune", "Delhi", "Kolkata"]
        institutions = [
            "IIT Madras", "IIT Delhi", "IIT Bombay", "BITS Pilani",
            "Anna University", "Delhi University", "IIM Bangalore"
        ]
        companies = [
            "Infosys", "Tata Consultancy Services", "Wipro",
            "Zoho Corporation", "Freshworks", "Tech Mahindra"
        ]

        return {
            "first_name": first_name,
            "last_name": last_name,
            "full_name": full_name,
            "formal_alias": f"Mr. {last_name}" if random.random() > 0.5 else f"Ms. {last_name}",
            "email": email,
            "phone": phone,
            "city": random.choice(cities),
            "institution": random.choice(institutions),
            "company": random.choice(companies),
            "pan": pan_number,
            "age": str(random.randint(21, 55)),
            "role": random.choice(["Software Engineer", "Data Analyst", "Research Scholar", "Project Lead"]),
        }

    def _build_turn(
        self,
        turn_number: int,
        template: str,
        slot_map: dict[str, tuple[str, str, str]],  # key -> (text, entity_type, category)
        entity_registry: dict[str, EntityGroundTruth],
    ) -> ConversationTurn:
        """
        Assemble a conversation turn from a template and compute exact
        character spans for ground-truth annotations.
        """
        # Sort slot keys by length descending to avoid partial substitution
        sorted_keys = sorted(slot_map.keys(), key=len, reverse=True)

        # Build prompt by replacing placeholders
        prompt = template
        for k in sorted_keys:
            val = slot_map[k][0]
            prompt = prompt.replace(f"{{{k}}}", val)

        # Now locate exact offsets for each slot
        annotations: list[EntityAnnotation] = []
        disclosed_entity_ids: list[str] = []

        for k, (val, entity_type, category) in slot_map.items():
            if f"{{{k}}}" in template:
                # Find all occurrences of this entity text in prompt
                start = 0
                while True:
                    idx = prompt.find(val, start)
                    if idx == -1:
                        break

                    entity_id = f"E_{val.replace(' ', '_').lower()[:15]}"

                    annotations.append(
                        EntityAnnotation(
                            entity_id=entity_id,
                            entity_type=entity_type,
                            text=val,
                            start=idx,
                            end=idx + len(val),
                            identifier_category=category,
                        )
                    )

                    if entity_id not in disclosed_entity_ids:
                        disclosed_entity_ids.append(entity_id)

                    # Update registry
                    if entity_id not in entity_registry:
                        entity_registry[entity_id] = EntityGroundTruth(
                            entity_id=entity_id,
                            canonical_name=val,
                            entity_type=entity_type,
                            identifier_category=category,
                            aliases=[val],
                            first_disclosed_turn=turn_number,
                        )
                    else:
                        if val not in entity_registry[entity_id].aliases:
                            entity_registry[entity_id].aliases.append(val)

                    start = idx + len(val)

        # Sort annotations by character position
        annotations.sort(key=lambda a: a.start)

        return ConversationTurn(
            turn_number=turn_number,
            user_prompt=prompt,
            disclosed_entity_ids=disclosed_entity_ids,
            annotations=annotations,
        )

    def generate_conversation(self, index: int) -> SyntheticConversation:
        """Generate a complete multi-turn scenario conversation."""
        profile = self._generate_indian_profile()
        scenarios = ["college_academic", "hr_workplace", "finance_banking", "legal_administrative"]
        scenario = scenarios[index % len(scenarios)]

        entity_registry: dict[str, EntityGroundTruth] = {}
        turns: list[ConversationTurn] = []

        if scenario == "college_academic":
            # Scenario: Student advising with gradual disclosure
            # Turn 1: Inquiry (Quasi-ID: Institution)
            t1 = self._build_turn(
                turn_number=1,
                template="Hello! I am a student at {institution} preparing for my final semester elective selection.",
                slot_map={
                    "institution": (profile["institution"], "LOCATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            # Turn 2: Major & City (Quasi-ID)
            t2 = self._build_turn(
                turn_number=2,
                template="I am based in {city} and specializing in {role}. Can you recommend advanced privacy engineering electives?",
                slot_map={
                    "city": (profile["city"], "LOCATION", CATEGORY_QUASI),
                    "role": (profile["role"], "OCCUPATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            # Turn 3: Name & Direct ID introduction
            t3 = self._build_turn(
                turn_number=3,
                template="By the way, my name is {full_name}. My department advisor suggested I contact the lab coordinator.",
                slot_map={
                    "full_name": (profile["full_name"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            # Turn 4: Contact details (Direct ID)
            t4 = self._build_turn(
                turn_number=4,
                template="If needed, you can reach me directly at {email} or {phone}.",
                slot_map={
                    "email": (profile["email"], "EMAIL_ADDRESS", CATEGORY_DIRECT),
                    "phone": (profile["phone"], "PHONE_NUMBER", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            # Turn 5: Alias reference
            t5 = self._build_turn(
                turn_number=5,
                template="Please draft an email on behalf of {first_name} to the departmental committee requesting approval.",
                slot_map={
                    "first_name": (profile["first_name"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            turns = [t1, t2, t3, t4, t5]

        elif scenario == "hr_workplace":
            # Scenario: Job application & verification
            t1 = self._build_turn(
                turn_number=1,
                template="Hi, I am currently working as a {role} at {company} in {city}.",
                slot_map={
                    "role": (profile["role"], "OCCUPATION", CATEGORY_QUASI),
                    "company": (profile["company"], "ORGANIZATION", CATEGORY_QUASI),
                    "city": (profile["city"], "LOCATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            t2 = self._build_turn(
                turn_number=2,
                template="My name is {full_name}. I am preparing an updated CV for an internal transfer.",
                slot_map={
                    "full_name": (profile["full_name"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t3 = self._build_turn(
                turn_number=3,
                template="Here are my official contact coordinates: {email} and mobile {phone}.",
                slot_map={
                    "email": (profile["email"], "EMAIL_ADDRESS", CATEGORY_DIRECT),
                    "phone": (profile["phone"], "PHONE_NUMBER", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t4 = self._build_turn(
                turn_number=4,
                template="HR asked me to provide my tax identifier for background clearance: PAN is {pan}.",
                slot_map={
                    "pan": (profile["pan"], "IN_PAN", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t5 = self._build_turn(
                turn_number=5,
                template="Can you format a cover letter addressing me as {formal_alias}?",
                slot_map={
                    "formal_alias": (profile["formal_alias"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            turns = [t1, t2, t3, t4, t5]

        elif scenario == "finance_banking":
            # Scenario: Banking & Tax inquiry
            t1 = self._build_turn(
                turn_number=1,
                template="I want to understand the tax rebate limits under Section 87A for residents in {city}.",
                slot_map={
                    "city": (profile["city"], "LOCATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            t2 = self._build_turn(
                turn_number=2,
                template="I am {full_name}, employed as a {role} at {company}.",
                slot_map={
                    "full_name": (profile["full_name"], "PERSON", CATEGORY_DIRECT),
                    "role": (profile["role"], "OCCUPATION", CATEGORY_QUASI),
                    "company": (profile["company"], "ORGANIZATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            t3 = self._build_turn(
                turn_number=3,
                template="My registered bank communication email is {email}.",
                slot_map={
                    "email": (profile["email"], "EMAIL_ADDRESS", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t4 = self._build_turn(
                turn_number=4,
                template="For the verification form, my phone is {phone} and PAN number is {pan}.",
                slot_map={
                    "phone": (profile["phone"], "PHONE_NUMBER", CATEGORY_DIRECT),
                    "pan": (profile["pan"], "IN_PAN", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t5 = self._build_turn(
                turn_number=5,
                template="Summarize the deductions applicable for {first_name} in one bullet list.",
                slot_map={
                    "first_name": (profile["first_name"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            turns = [t1, t2, t3, t4, t5]

        else:  # legal_administrative
            # Scenario: Rental / Agreement
            t1 = self._build_turn(
                turn_number=1,
                template="I need assistance reviewing standard clauses in a residential lease agreement for an apartment in {city}.",
                slot_map={
                    "city": (profile["city"], "LOCATION", CATEGORY_QUASI),
                },
                entity_registry=entity_registry,
            )
            t2 = self._build_turn(
                turn_number=2,
                template="The tenant listed in the draft is {full_name}.",
                slot_map={
                    "full_name": (profile["full_name"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t3 = self._build_turn(
                turn_number=3,
                template="Please include notice contact details: email {email} and emergency phone {phone}.",
                slot_map={
                    "email": (profile["email"], "EMAIL_ADDRESS", CATEGORY_DIRECT),
                    "phone": (profile["phone"], "PHONE_NUMBER", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t4 = self._build_turn(
                turn_number=4,
                template="The landlord requested tenant identity verification using PAN {pan}.",
                slot_map={
                    "pan": (profile["pan"], "IN_PAN", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            t5 = self._build_turn(
                turn_number=5,
                template="Generate the final signature block for {formal_alias}.",
                slot_map={
                    "formal_alias": (profile["formal_alias"], "PERSON", CATEGORY_DIRECT),
                },
                entity_registry=entity_registry,
            )
            turns = [t1, t2, t3, t4, t5]

        # Link aliases under same parent canonical entities
        person_entities = [
            e for e in entity_registry.values() if e.entity_type == "PERSON"
        ]
        if person_entities:
            # Consolidate aliases under the full name
            full_name_ent = next(
                (e for e in person_entities if e.canonical_name == profile["full_name"]),
                person_entities[0]
            )
            for p_ent in person_entities:
                if p_ent.canonical_name != full_name_ent.canonical_name:
                    if p_ent.canonical_name not in full_name_ent.aliases:
                        full_name_ent.aliases.append(p_ent.canonical_name)

        return SyntheticConversation(
            conversation_id=f"synth_en_in_{index + 1:03d}",
            scenario=scenario,
            dataset_source="faker_en_in_controlled_generator",
            license="CC-BY-4.0 / Research Use Only",
            provenance={
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "faker_locale": "en_IN",
                "generator_version": "1.0.0",
                "random_seed": self.seed,
            },
            ground_truth_profile=profile,
            entities=list(entity_registry.values()),
            turns=turns,
        )

    def generate_dataset(self, count: int = 10) -> list[dict[str, Any]]:
        """Generate a complete batch of synthetic conversations."""
        if self.seed is not None:
            self.fake.seed_instance(self.seed)
            random.seed(self.seed)
        return [self.generate_conversation(i).to_dict() for i in range(count)]


# ── CLI Runner ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Indian multi-turn dataset.")
    parser.add_argument("--count", type=int, default=10, help="Number of conversations to generate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument(
        "--out",
        type=str,
        default="data/synthetic/synthetic_conversations_v1.json",
        help="Output path for the generated JSON dataset",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.count} synthetic conversations (seed={args.seed})...")
    generator = SyntheticDatasetGenerator(seed=args.seed)
    dataset = generator.generate_dataset(count=args.count)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"✓ Successfully generated {len(dataset)} conversations!")
    print(f"✓ Saved to: {out_path.resolve()}")


if __name__ == "__main__":
    main()
