import os,random,hashlib,time,math
from collections import Counter
from Crypto.PublicKey import RSA
from typing import Union, Tuple
import numpy as np
from scipy.stats import chisquare

class ShannonEntropy:
    @staticmethod
    def shannon(val):
        if isinstance(val,int):
            val = val.to_bytes((val.bit_length() + 7) // 8,"big")
        elif isinstance(val,str):
            val = val.encode()
        if not val: return 0.0
        counts = Counter(val)
        return -sum((c / len(val)) * math.log2(c / len(val)) for c in counts.values())

    @staticmethod
    def fingerprint(key):
        data = f"{key.n}:{key.e}".encode()
        return hashlib.sha256(data).hexdigest()
    
class NISTTests:
    @staticmethod
    def _to_bits(val):
        if isinstance(val,int):
            return bin(val)[2:]
        return ''.join(f"{b:08b}" for b in val)

    @staticmethod
    def frequency(bits):
        n = len(bits)
        S = sum(1 if b == '1' else -1 for b in bits)
        test_stat = abs(S) / math.sqrt(n)
        p = math.erfc(test_stat / math.sqrt(2))
        return p

    @staticmethod
    def block_frequency(bits,block_size=128):
        n = len(bits)
        if n < block_size:
            return 0.0
        num_blocks = n // block_size
        blocks = [bits[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
        proportions = [block.count('1')/block_size for block in blocks]

        chi_sq = 4*block_size * sum((p - 0.5)**2 for p in proportions)
        p = math.erfc(math.sqrt(chi_sq)/math.sqrt(2))
        return p

    @staticmethod
    def runs(bits):
        n = len(bits)
        pi = bits.count('1') / n
        if abs(pi - 0.5) >= 0.25: return 0.0
        V = 1 + sum(bits[i] != bits[i-1] for i in range(1,n))
        return math.erfc(abs(V - 2*n*pi*(1-pi)) / (2*math.sqrt(2*n)*pi*(1-pi)))

    @staticmethod
    def longest_run(bits):
        runs = [len(r) for r in bits.split('0')]
        max_run = max(runs)
        # !!! very rough acceptance threshold
        return 1.0 if max_run < 34 else 0.0

    @staticmethod
    def approximate_entropy(bits,m=5):
        def phi(m):
            counts = {}
            for i in range(len(bits)):
                seq = bits[i:i+m]
                if len(seq) == m:
                    counts[seq] = counts.get(seq,0) + 1

            C = [c/len(bits) for c in counts.values()]
            return sum(c * math.log(c) for c in C)

        phi_m = phi(m)
        phi_m1 = phi(m+1)
        ApEn = phi_m - phi_m1
        p = math.exp(-2 * len(bits) * ApEn)
        return p

    @staticmethod
    def chi_square(bits: str, num_bins: int = 16) -> Tuple[float, float]:
        # We need to obtain observed frequencies of byte values (0-255)
        # and the expected frequencies assuming uniform distribution to pass
        # in to scipy.stats.chisquare

        n = len(bits)
        if n < 8: return (0.0, 0.0)
        
        # Convert bits to bytes
        byte_values = [] # list of byte values
        for i in range(0, n - 7, 8): # Step by 8 bits in our bitstream
            byte_str = bits[i:i+8] # Get 8 bits
            byte_val = int(byte_str, 2) # Convert to integer
            byte_values.append(byte_val) # Append to list
        
        if len(byte_values) < num_bins:
            return (0.0, 0.0)
        
        # Count observed frequencies for all 256 possible byte values
        observed = np.zeros(256, dtype=int) # Initialize counts to zero for each type of byte
        for val in byte_values:
            observed[val] += 1 # Increment count for this byte value
        
        # Expected frequency for uniform distribution, each byte value should appear equally often
        # We expect each byte value to appear (no. of bytes) / 256 times
        expected = np.full(256, len(byte_values) / 256)
        
        # Pass to chisquare function
        chi_sq, p_value = chisquare(f_obs=observed, f_exp=expected)
        
        return (chi_sq, p_value)

    @staticmethod
    def predictability(key_n: bytes) -> float:
        # Predictability assesses the correlation between successive RNG outputs
        # Formula: r = Σ(x_i - μ)(x_{i+1} - μ) / Σ(x_i - μ)²
        # Numerator sums till len(x)-1, denominator sums all x
        # Returns: Correlation coefficient r. Value closer to zero indicates lower predictability.
        
        # Convert bytes to list of integers
        x = list(key_n)
        
        # Need at least 2 values to compute correlation
        if len(x) < 2: return 0.0
        
        # Calculate mean
        μ = sum(x) / len(x)
        
        # Calculate numerator: Σ(x_i - μ)(x_{i+1} - μ)
        numerator = 0.0
        for i in range(len(x) - 1): # sum up to len(x)-1
            numerator += (x[i] - μ) * (x[i+1] - μ)
        
        # Calculate denominator: Σ(x_i - μ)², sum all x
        denominator = 0.0
        for i in range(len(x)):
            diff = x[i] - μ
            denominator += diff ** 2
        
        # Avoid division by zero
        if denominator == 0: return 0.0
        return numerator / denominator
    
class RSAUtil:
    @staticmethod
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

class RSAExperimentBase:
    def __init__(self, n_keys=10, key_size=1024):
        self.n_keys = n_keys
        self.key_size = key_size
        self.results = []   # stores (key, fp, entropy)

    def gen_seed(self, _):
        raise NotImplementedError

    def apply_seed(self, seed):
        raise NotImplementedError

    def run(self):
        print(f"--- Running {self.n_keys} RSA key generations ---")
        for i in range(self.n_keys):
            seed = self.gen_seed(i)
            self.apply_seed(seed)
            t0 = time.time()
            if hasattr(self, '_mt_rng'):
                key = RSA.generate(self.key_size, randfunc=self._mt_rng.get_bytes)
            else:
                key = RSA.generate(self.key_size)  # OS entropy baseline
            t1 = time.time() - t0

            fp = ShannonEntropy.fingerprint(key)
            ent = ShannonEntropy.shannon(key.n)

            self.results.append((key, fp, ent,t1))
            print(f"Key {i+1}: Entropy={ent:.2f}, FP={fp[:8]}..., Time={t1:.4f}s")

        print()

    def analyze(self):
        print(f"--- Analysis of generated keys ---")

        fps = [fp for _, fp, _, _ in self.results]
        entropies = [ent for _, _, ent, _ in self.results]
        times = [t1 for _, _, _, t1 in self.results]

        total_keys = self.n_keys
        unique_keys = len(set(fps))
        keys_duplicate = total_keys - unique_keys

        print(f"Total keys: {total_keys}")
        print(f"Unique keys: {unique_keys}")
        print(f"Duplicate keys: {keys_duplicate}")
        avg_time = sum(times)/len(times)
        print(f"Avg time per key: {avg_time:.4f}s")

        avg_entropy = sum(entropies)/len(entropies)
        min_entropy = min(entropies)
        max_entropy = max(entropies)

        print(f"Shannon Entropy (modulus) stats:")
        print(f"  Avg: {avg_entropy:.4f} bits/byte")
        print(f"  Min: {min_entropy:.4f}")
        print(f"  Max: {max_entropy:.4f}\n")

        # -------------------------
        # NIST Tests
        # -------------------------
        print("NIST SP 800-22 Tests (modulus bits)")
        nist_summary = {
            "frequency": 0,
            "block_frequency": 0,
            "runs": 0,
            "longest_run": 0,
            "approx_entropy": 0,
            "chi_square": 0
        }

        for idx, (key, _, _, _) in enumerate(self.results):
            bits = NISTTests._to_bits(key.n)

            p1 = NISTTests.frequency(bits)
            p2 = NISTTests.block_frequency(bits)
            p3 = NISTTests.runs(bits)
            p4 = NISTTests.longest_run(bits)
            p5 = NISTTests.approximate_entropy(bits)
            chi_stat, p6 = NISTTests.chi_square(bits, return_statistic=True)

            if p1 >= 0.01: nist_summary["frequency"] += 1
            if p2 >= 0.01: nist_summary["block_frequency"] += 1
            if p3 >= 0.01: nist_summary["runs"] += 1
            if p4 >= 0.01: nist_summary["longest_run"] += 1
            if p5 >= 0.01: nist_summary["approx_entropy"] += 1
            if p6 >= 0.01: nist_summary["chi_square"] += 1

            print(f"Key {idx+1}:")
            print(f"  Frequency test p={p1:.4f}")
            print(f"  Block freq p={p2:.4f}")
            print(f"  Runs test p={p3:.4f}")
            print(f"  Longest run p={p4:.4f}")
            print(f"  Approx entropy p={p5:.4f}")
            print(f"  Chi-square test: χ²={chi_stat:.4f}, p={p6:.4f}\n")

        # -------------------------
        # NIST Summary
        # -------------------------
        print("NIST Test Summary:")
        for test, passed in nist_summary.items():
            print(f"  {test.replace('_',' ').title()}: {passed}/{total_keys} passed")

        # -------------------------
        # Shared Factor Check (very important!)
        # -------------------------
        shared = 0
        for i, (k1, _, _, _) in enumerate(self.results):
            for j, (k2, _, _, _) in enumerate(self.results[i+1:], i+1):
                if RSAUtil.gcd(k1.n, k2.n) > 1:
                    shared += 1
                    print(f"  Keys {i+1} & {j+1} share a factor!")

        if shared == 0:
            print("\nNo shared factors detected.")
        else:
            print(f"\nTotal pairs with shared factors: {shared}")

        # -------------------------
        # Conclusions
        # -------------------------
        print("\nConclusion:")
        if keys_duplicate > 0:
            print("  Low entropy caused duplicate keys.")
        if shared > 0:
            print("  Low entropy caused keys to share factors.")
        if avg_entropy < 7.5:
            print("  Modulus entropy lower than expected; randomness weak.")

        # NIST pass rate
        nist_pass_rate = sum(nist_summary.values()) / (6 * total_keys)

        if nist_pass_rate < 0.5:
            print("  Most NIST tests did not pass — randomness is weak.")
        elif nist_pass_rate < 0.8:
            print("  NIST results are mixed — randomness questionable.")
        else:
            print("  NIST results look healthy — randomness acceptable.")

        print()

class MTByteGenerator:
    def __init__(self, seed_bytes):
        # Seed MT with your low-entropy seed
        seed_int = int.from_bytes(seed_bytes, "big")
        random.seed(seed_int)

    def get_bytes(self, n):
        # Produce n bytes from MT PRNG
        return bytes([random.getrandbits(8) for _ in range(n)])


class MTBaseline(RSAExperimentBase):
    def __init__(self, n_keys=10, entropy_bits=16, key_size=1024):
        super().__init__(n_keys, key_size)
        self.entropy_bytes = entropy_bits // 8

    def gen_seed(self, _):
        return os.urandom(self.entropy_bytes)

    def apply_seed(self, seed):
        self._mt_rng = MTByteGenerator(seed)


class OSBaseline(RSAExperimentBase):
    def gen_seed(self, _):
        return None  # unused

    def apply_seed(self, seed):
        # DO NOTHING — RSA.generate now uses SystemRandom exclusively
        random.seed()  # reseed using OS entropy, not custom seed

def main():
    print("\n==============================")
    print(" Baseline A: Mersenne Twister")
    print("==============================")
    mt = MTBaseline(n_keys=10, entropy_bits=16)
    mt.run()
    mt.analyze()

    print("\n==============================")
    print(" Baseline B: SystemRandom (OS entropy)")
    print("==============================")
    osrng = OSBaseline(n_keys=10)
    osrng.run()
    osrng.analyze()

if __name__ == "__main__":
    main()
