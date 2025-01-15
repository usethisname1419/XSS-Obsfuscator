import random
import base64
import urllib.parse
import argparse
from itertools import combinations

# Define obfuscation techniques for XSS payloads
def random_case(payload):
    """Randomly capitalize letters."""
    return ''.join(
        char.upper() if random.choice([True, False]) else char.lower()
        for char in payload
    )


def insert_tag_mimicry(payload):
    """Insert tag-like mimics for broader coverage."""
    mimic_tags = ['<script>', '<div>', '<img>', '<a>', '<span>', '<body>', '<style>', '<iframe>']
    for tag in mimic_tags:
        payload = payload.replace(tag, f'<SCR<{tag[1:]}>IPT>')
        payload = payload.replace(tag.replace('<', '</'), f'</SCR<{tag[2:]}IPT>')
    return payload


def base64_encode(payload):
    """Base64 encode the payload."""
    return base64.b64encode(payload.encode()).decode()


def url_encode(payload):
    """URL encode the payload."""
    return urllib.parse.quote(payload)


def unicode_encode(payload):
    """Unicode encode the payload."""
    return ''.join(f"\\u{ord(char):04x}" for char in payload)


def html_entity_encode(payload):
    """HTML entity encode the payload."""
    return ''.join(f"&#{ord(char)};" for char in payload)


def hex_encode(payload):
    """Encode payload in hex."""
    return ''.join(f"%{ord(char):02x}" for char in payload)


def reverse_payload(payload):
    """Reverse the payload."""
    return payload[::-1]


def random_unicode_insert(payload):
    """Insert random Unicode characters around payload."""
    random_unicode = ''.join(chr(random.randint(0x0400, 0x04FF)) for _ in range(3))
    return f"{random_unicode}{payload}{random_unicode}"


def add_spacing(payload):
    """Add random spaces in the payload."""
    return ''.join(
        char + (' ' if random.choice([True, False]) else '') for char in payload
    )


def double_encode(payload):
    """Double URL encode the payload."""
    return urllib.parse.quote(urllib.parse.quote(payload))


def pad_payload(payload, size=32768):
    """Pad the payload to a specific size."""
    padding = 'A' * (size - len(payload))
    return payload + padding


def js_escape(payload):
    """Escape payload for JavaScript."""
    return ''.join(f"\\x{ord(char):02x}" for char in payload)


def bitwise_obfuscate(payload):
    """Obfuscate using bitwise operations."""
    return ''.join(f"{ord(char) ^ 0xAA:02x}" for char in payload)


def concatenate_chars(payload):
    """Concatenate characters for obfuscation."""
    return '||'.join(f"'{char}'" for char in payload)


def insert_null_bytes(payload):
    """Insert null bytes between characters."""
    return ''.join(f"{char}\x00" for char in payload)


def comment_obfuscation(payload):
    """Insert random comments to break up payload."""
    return ''.join(f"{char}/*{random.randint(1000, 9999)}*/" for char in payload)


def mixed_obfuscation(payload, num_techniques=3):
    """Apply a random mix of obfuscation techniques."""
    techniques = [
        random_case,
        insert_tag_mimicry,
        base64_encode,
        url_encode,
        unicode_encode,
        html_entity_encode,
        hex_encode,
        reverse_payload,
        random_unicode_insert,
        add_spacing,
        double_encode,
        js_escape,
        bitwise_obfuscate,
        concatenate_chars,
        insert_null_bytes,
        comment_obfuscation,
    ]

    chosen_techniques = random.sample(techniques, num_techniques)
    for technique in chosen_techniques:
        payload = technique(payload)
    return payload


# Apply every obfuscation technique to each payload
def apply_all_techniques(payload):
    techniques = [
        random_case,
        insert_tag_mimicry,
        base64_encode,
        url_encode,
        unicode_encode,
        html_entity_encode,
        hex_encode,
        reverse_payload,
        random_unicode_insert,
        add_spacing,
        double_encode,
        js_escape,
        bitwise_obfuscate,
        concatenate_chars,
        insert_null_bytes,
        comment_obfuscation,
    ]

    obfuscated_payloads = []
    for technique in techniques:
        obfuscated_payloads.append(technique(payload))
    return obfuscated_payloads


# Load payloads from a file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]


# Write obfuscated payloads to a file
def write_payloads(obfuscated_payloads, output_file):
    with open(output_file, 'w') as file:
        for payload in obfuscated_payloads:
            file.write(payload + '\n')


# Main function using argparse
def main():
    parser = argparse.ArgumentParser(description="XSS Payload Obfuscation Tool")
    parser.add_argument('-in', '--input_file', required=True, help="Input file containing raw payloads")
    parser.add_argument('-out', '--output_file', required=True, help="Output file for obfuscated payloads")
    args = parser.parse_args()

    payloads = load_payloads(args.input_file)
    obfuscated_payloads = []
    for payload in payloads:
        obfuscated_payloads.extend(apply_all_techniques(payload))
        obfuscated_payloads.append(mixed_obfuscation(payload, num_techniques=3))

    write_payloads(obfuscated_payloads, args.output_file)


if __name__ == '__main__':
    main()

