import os, random, hashlib, time, math
from collections import Counter
from Crypto.PublicKey import RSA

# Simulate low-entropy startup
class LowEntropySim:
    def __init__(self, bits=16):
        self.bytes_needed = bits // 8

    def get_seed(self):
        return os.urandom(self.bytes_needed)

# Simple entropy analysis
class Entropy:
    @staticmethod
    def shannon(val):
        if isinstance(val, int):
            val = val.to_bytes((val.bit_length() + 7) // 8, "big")
        elif isinstance(val, str):
            val = val.encode()
        if not val: return 0.0
        counts = Counter(val)
        return -sum((c / len(val)) * math.log2(c / len(val)) for c in counts.values())

    @staticmethod
    def fingerprint(key):
        data = f"{key.n}:{key.e}".encode()
        return hashlib.sha256(data).hexdigest()

# RSA utilities
class RSAUtil:
    @staticmethod
    def generate_key(size=1024, seed=None):
        if seed: random.seed(seed)
        return RSA.generate(size)

    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

# Main experiment
class Experiment:
    def __init__(self, n_keys=10, entropy_bits=16, key_size=1024):
        self.n_keys, self.key_size = n_keys, key_size
        self.sim = LowEntropySim(entropy_bits)
        self.results = []

    def run(self):
        print(f"Running {self.n_keys} keys with {self.sim.bytes_needed*8} bits entropy")
        for i in range(self.n_keys):
            seed = self.sim.get_seed()
            key = RSAUtil.generate_key(self.key_size, seed)
            fp = Entropy.fingerprint(key)
            ent = Entropy.shannon(key.n)
            self.results.append((key, seed, fp, ent))
            print(f"Key {i+1}: entropy={ent:.2f}, fingerprint={fp[:8]}...")
        print()

    def analyze(self):
        print("Analysis of generated keys")
        print("-" * 40)

        fps = [r[2] for r in self.results]
        entropies = [r[3] for r in self.results]
        keys_total = self.n_keys
        keys_unique = len(set(fps))
        keys_duplicate = keys_total - keys_unique

        print(f"Total keys: {keys_total}")
        print(f"Unique keys: {keys_unique}")
        print(f"Duplicate keys: {keys_duplicate}")

        avg_entropy = sum(entropies)/len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)

        print(f"Entropy (modulus) stats:")
        print(f"  Avg: {avg_entropy:.4f} bits/byte")
        print(f"  Min: {min_entropy:.4f}")
        print(f"  Max: {max_entropy:.4f}")

        # GCD analysis
        shared = 0
        for i, (k1, *_ ) in enumerate(self.results):
            for j, (k2, *_ ) in enumerate(self.results[i+1:], i+1):
                if RSAUtil.gcd(k1.n, k2.n) > 1:
                    shared += 1
                    print(f"Keys {i+1} & {j+1} share a factor")

        if shared == 0:
            print("No shared factors detected.")
        else:
            print(f"Total pairs with shared factors: {shared}")

        # Phase conclusion
        print("Conclusion:")
        if keys_duplicate > 0:
            print("  Low entropy caused duplicate keys.")
        elif shared > 0:
            print("  Low entropy caused keys to share factors.")
        elif avg_entropy < 7.5:
            print("  Modulus entropy lower than expected; randomness weak.")
        else:
            print("  No significant weaknesses detected.")

        print("=" * 40)

def main():
    print("=== Phase 1: Low entropy 16 bits ===")
    exp1 = Experiment(n_keys=10, entropy_bits=16)
    exp1.run()
    exp1.analyze()

    print("=== Phase 2: Moderate entropy 32 bits ===")
    exp2 = Experiment(n_keys=10, entropy_bits=32)
    exp2.run()
    exp2.analyze()

if __name__ == "__main__":
    main()
