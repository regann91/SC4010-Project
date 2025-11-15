import os,random,hashlib,time,math
from collections import Counter
from Crypto.PublicKey import RSA
from typing import Union, Tuple

class LowEntropySim:
    def __init__(self,bits=16):
        self.bytes_needed = bits // 8

    def get_seed(self):
        return os.urandom(self.bytes_needed)

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
        if abs(pi - 0.5) >= 0.25:
            return 0.0  # auto fail

        V = 1
        for i in range(1,n):
            if bits[i] != bits[i-1]:
                V += 1

        p = math.erfc(abs(V - 2*n*pi*(1-pi)) /
                      (2*math.sqrt(2*n)*pi*(1-pi)))
        return p

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
    def chi_square(bits: str, num_bins: int = 16, return_statistic: bool = False) -> Union[float, Tuple[float, float]]:
        """Chi-square test for uniformity of random bits.
        Divides bits into bytes and checks if byte values are uniformly distributed.
        
        Args:
            bits: Binary string to test
            num_bins: Number of bins for chi-square test (default 16)
            return_statistic: If True, returns (statistic, p_value), else just p_value
        
        Returns:
            Union[float, Tuple[float, float]]: Either p_value alone or (chi_square_statistic, p_value)
        """
        n = len(bits)
        if n < 8:
            return (0.0, 0.0) if return_statistic else 0.0
        
        # Convert bits to bytes
        byte_values = []
        for i in range(0, n - 7, 8):
            byte_str = bits[i:i+8]
            byte_val = int(byte_str, 2)
            byte_values.append(byte_val)
        
        if len(byte_values) < num_bins:
            return (0.0, 0.0) if return_statistic else 0.0
        
        # Count frequencies for all 256 possible byte values
        observed = [0] * 256
        for val in byte_values:
            observed[val] += 1
        
        # Expected frequency for uniform distribution
        expected = len(byte_values) / 256
        
        # Calculate chi-square statistic
        chi_sq = sum((obs - expected)**2 / expected for obs in observed if expected > 0)
        
        # Degrees of freedom = 256 - 1 = 255
        df = 255
        
        # Calculate p-value using incomplete gamma function (upper tail)
        # P(X >= chi_sq) where X ~ chi-square(df)
        # Using the regularized incomplete gamma function: Q(df/2, chi_sq/2)
        def igamc(a, x):
            """Complementary incomplete gamma function (upper tail)"""
            if x < 0 or a <= 0:
                return 0.0
            if x == 0:
                return 1.0
            
            # Use continued fraction expansion for better accuracy
            ax = a * math.log(x) - x - math.lgamma(a)
            if ax < -700:
                return 0.0
            
            ax = math.exp(ax)
            
            # Continued fraction
            y = 1.0 - a
            z = x + y + 1.0
            c = 0.0
            pkm2 = 1.0
            qkm2 = x
            pkm1 = x + 1.0
            qkm1 = z * x
            ans = pkm1 / qkm1
            
            for i in range(100):
                c += 1.0
                y += 1.0
                z += 2.0
                yc = y * c
                pk = pkm1 * z - pkm2 * yc
                qk = qkm1 * z - qkm2 * yc
                
                if qk != 0:
                    r = pk / qk
                    t = abs((ans - r) / r)
                    ans = r
                    
                    if t < 1e-10:
                        break
                    
                pkm2 = pkm1
                pkm1 = pk
                qkm2 = qkm1
                qkm1 = qk
                
                # Rescale to prevent overflow
                if abs(pk) > 1e30:
                    pkm2 /= 1e30
                    pkm1 /= 1e30
                    qkm2 /= 1e30
                    qkm1 /= 1e30
            
            return ans * ax
        
        try:
            p_value = igamc(df / 2.0, chi_sq / 2.0)
            p_value = max(0.0, min(1.0, p_value))
        except:
            p_value = 0.5
        
        return (chi_sq, p_value) if return_statistic else p_value

class RSAUtil:
    @staticmethod
    def generate_key(size=1024,seed=None):
        if seed: random.seed(seed)
        return RSA.generate(size)

    @staticmethod
    def gcd(a,b):
        while b:
            a,b = b,a % b
        return a

class Experiment:
    def __init__(self,n_keys=10,entropy_bits=16,key_size=1024):
        self.n_keys,self.key_size = n_keys,key_size
        self.sim = LowEntropySim(entropy_bits)
        self.results = []

    def run(self):
        print(f"Running {self.n_keys} keys with {self.sim.bytes_needed*8} bits entropy")
        for i in range(self.n_keys):
            seed = self.sim.get_seed()
            key = RSAUtil.generate_key(self.key_size,seed)
            fp = ShannonEntropy.fingerprint(key)
            ent = ShannonEntropy.shannon(key.n)
            self.results.append((key,seed,fp,ent))
            print(f"Key {i+1}: entropy={ent:.2f},fingerprint={fp[:8]}...")
        print()

    def analyze(self):
        print(f"--- Analysis of generated keys ---")
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

        print(f"Shannon Entropy (modulus) stats:")
        print(f"  Avg: {avg_entropy:.4f} bits/byte")
        print(f"  Min: {min_entropy:.4f}")
        print(f"  Max: {max_entropy:.4f}")

        print(f"NIST SP 800-22 Tests (modulus bits)")
        nist_summary = {
            "frequency": 0,
            "block_frequency": 0,
            "runs": 0,
            "longest_run": 0,
            "approx_entropy": 0,
            "chi_square": 0
        }
        total_tests = len(self.results)
        for idx,(key,*_ ) in enumerate(self.results):
            bits = NISTTests._to_bits(key.n)
            p1 = NISTTests.frequency(bits)
            p2 = NISTTests.block_frequency(bits)
            p3 = NISTTests.runs(bits)
            p4 = NISTTests.longest_run(bits)
            p5 = NISTTests.approximate_entropy(bits)
            chi_result = NISTTests.chi_square(bits, return_statistic=True)
            chi_stat, p6 = chi_result if isinstance(chi_result, tuple) else (0.0, chi_result)

            if p1 >= 0.01: nist_summary["frequency_test"] += 1
            if p2 >= 0.01: nist_summary["block_frequency_test"] += 1
            if p3 >= 0.01: nist_summary["runs_test"] += 1
            if p4 >= 0.01: nist_summary["longest_run"] += 1
            if p5 >= 0.01: nist_summary["approx_entropy"] += 1
            if p6 >= 0.01: nist_summary["chi_square"] += 1

            print(f"Key {idx+1}:")
            print(f"  Frequency test p={p1:.4f}")
            print(f"  Block freq p={p2:.4f}")
            print(f"  Runs test p={p3:.4f}")
            print(f"  Longest run p={p4:.4f}")
            print(f"  Approx entropy p={p5:.4f}")
            print(f"  Chi-square test: χ²={chi_stat:.4f}, p={p6:.4f}")
            
        print(f"NIST Test Summary:")
        for test,passed in nist_summary.items():
            print(f"  {test.replace('_',' ').title()}: {passed}/{total_tests} passed")

        shared = 0
        for i,(k1,*_ ) in enumerate(self.results):
            for j,(k2,*_ ) in enumerate(self.results[i+1:],i+1):
                if RSAUtil.gcd(k1.n,k2.n) > 1:
                    shared += 1
                    print(f"Keys {i+1} & {j+1} share a factor")

        if shared == 0:
            print("No shared factors detected.")
        else:
            print(f"Total pairs with shared factors: {shared}")

        print("Conclusion:")
        if keys_duplicate > 0:
            print("  Low entropy caused duplicate keys.")
        if shared > 0:
            print("  Low entropy caused keys to share factors.")
        if avg_entropy < 7.5:
            print("  Modulus entropy lower than expected; randomness weak.")

        nist_pass_rate = sum(nist_summary.values()) / (5 * total_tests)

        if nist_pass_rate < 0.5:
            print("  Most NIST tests did not pass. The randomness in the generated keys appears weak.")
        elif nist_pass_rate < 0.8:
            print("  NIST results are mixed; some randomness is present but still questionable.")
        else:
            print("  NIST results look mostly healthy. No significant randomness issues detected.")

def main():
    print("=== Expt 1: Low entropy 16 bits ===")
    exp1 = Experiment(n_keys=10,entropy_bits=16)
    exp1.run()
    exp1.analyze()

    print("=== Expt 2: Moderate entropy 32 bits ===")
    exp2 = Experiment(n_keys=10,entropy_bits=32)
    exp2.run()
    exp2.analyze()

if __name__ == "__main__":
    main()
