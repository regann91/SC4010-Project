from phase2_emn import EMN_PRNG,SHA256CTR
from phase3_comparison import Phase3Compare
from phase4_analysis import (
    plot_entropy_comparison,
    plot_nist_pass_rates,
    plot_chi_square_comparison,
    plot_predictability_comparison
)

def main():
    
    emn = EMN_PRNG(P_seed=None,injection_frequency=10)

    def emn_randfunc():
        O = emn.next_output()
        ctr = SHA256CTR(O)
        return ctr.read

    cmp = Phase3Compare(
        num_keys=100,
        key_size=1024,
        emn_func=emn_randfunc
    )

    cmp.run()
    cmp.analyze()

    emn.stop()

    plot_entropy_comparison(cmp)
    plot_nist_pass_rates(cmp)
    plot_chi_square_comparison(cmp)
    plot_predictability_comparison(cmp)

if __name__ == "__main__":
    main()
