from phase2_emn import EMN_PRNG,SHA256CTR
from phase3_comparison import Phase3Compare
from phase4_analysis import (
    print_summary_table,
    plot_entropy_comparison,
    plot_nist_pass_rates,
    plot_chi_square_comparison,
    plot_predictability_comparison
)
import math

def main():

    NUM_KEYS = 2000
    TOTAL_INJECTIONS = 50
    # Ensure at least one injection
    INJECTION_FREQUENCY = max(math.ceil(NUM_KEYS / TOTAL_INJECTIONS), 1)

    emn = EMN_PRNG(P_seed=None,injection_frequency=INJECTION_FREQUENCY)
    def emn_randfunc():
        O = emn.next_output()
        ctr = SHA256CTR(O)
        return ctr.read

    cmp = Phase3Compare(
        num_keys=NUM_KEYS,
        key_size=1024,
        emn_func=emn_randfunc
    )

    cmp.run()
    cmp.analyze()

    emn.stop()

    print_summary_table(cmp)
    plot_entropy_comparison(cmp)
    plot_nist_pass_rates(cmp)
    plot_chi_square_comparison(cmp)
    plot_predictability_comparison(cmp)

if __name__ == "__main__":
    main()
