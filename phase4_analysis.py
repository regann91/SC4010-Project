import matplotlib.pyplot as plt
import math

def print_summary_table(cmp):
    """Display a graphical summary table comparing MT, OS, and EMN RNGs"""
    
    def avg(lst):
        return sum(lst) / len(lst) if lst else 0.0
    
    # Get stats for each RNG
    mt = cmp.stats["mt"]
    os_ = cmp.stats["os"]
    emn = cmp.stats["emn"]
    
    # Calculate metrics
    metrics = {}
    for label, data in [("EMN", emn), ("SystemRandom", os_), ("MersenneTwister", mt)]:
        # Chi-square statistic and p-value
        chi_stats = [entry["chi_stat"] for entry in data["nist"]]
        chi_pvals = [entry["chi"] for entry in data["nist"]]
        
        # Entropy
        entropy = avg(data["ents"])
        
        # Predictability
        predictability = avg(data["predictability"])
        
        # High-frequency time (avg time per key)
        time_avg = avg(data["times"])
        
        # Runs test (observed/expected)
        runs_obs = sum([entry["runs"] >= 0.01 for entry in data["nist"]])
        runs_total = len(data["nist"])
        
        metrics[label] = {
            "chi_stat": avg(chi_stats),
            "chi_pval": avg(chi_pvals),
            "entropy": entropy,
            "predictability": predictability,
            "time": time_avg,
            "runs": f"{runs_obs}/{runs_total}"
        }
    
    # Create table data
    row_labels = ['Chi-Squared Statistic', 'Chi-Squared p-value', 'Entropy', 'Predictability', 
                  'High-Frequency Time (seconds)', 'Runs Test (Passed/Total)']
    col_labels = ['EMN', 'SystemRandom', 'MersenneTwister']
    
    table_data = [
        [f"{metrics['EMN']['chi_stat']:.4f}", 
         f"{metrics['SystemRandom']['chi_stat']:.4f}", 
         f"{metrics['MersenneTwister']['chi_stat']:.4f}"],
        [f"{metrics['EMN']['chi_pval']:.4f}", 
         f"{metrics['SystemRandom']['chi_pval']:.4f}", 
         f"{metrics['MersenneTwister']['chi_pval']:.4f}"],
        [f"{metrics['EMN']['entropy']:.4f}", 
         f"{metrics['SystemRandom']['entropy']:.4f}", 
         f"{metrics['MersenneTwister']['entropy']:.4f}"],
        [f"{metrics['EMN']['predictability']:.4f}", 
         f"{metrics['SystemRandom']['predictability']:.4f}", 
         f"{metrics['MersenneTwister']['predictability']:.4f}"],
        [f"{metrics['EMN']['time']:.4f}", 
         f"{metrics['SystemRandom']['time']:.4f}", 
         f"{metrics['MersenneTwister']['time']:.4f}"],
        [metrics['EMN']['runs'], 
         metrics['SystemRandom']['runs'], 
         metrics['MersenneTwister']['runs']],
    ]
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.axis('tight')
    ax.axis('off')
    
    # Create table
    table = ax.table(cellText=table_data,
                     rowLabels=row_labels,
                     colLabels=col_labels,
                     cellLoc='center',
                     loc='center',
                     colWidths=[0.25, 0.25, 0.25])
    
    # Style the table
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 2)
    
    # Color header row
    for i in range(len(col_labels)):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # Color row labels
    for i in range(len(row_labels)):
        table[(i+1, -1)].set_facecolor('#E8E8E8')
        table[(i+1, -1)].set_text_props(weight='bold')
    
    plt.title('RNG Comparison Summary Table', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.show()

def plot_entropy_comparison(cmp):
    mt_ents = cmp.stats["mt"]["ents"]
    os_ents = cmp.stats["os"]["ents"]
    emn_ents = cmp.stats["emn"]["ents"]

    plt.figure(figsize=(12,6))
    plt.hist(mt_ents, bins=50, alpha=0.6, label="MT RNG")
    plt.hist(os_ents, bins=50, alpha=0.6, label="OS RNG")
    plt.hist(emn_ents, bins=50, alpha=0.6, label="EMN RNG")
    plt.xlabel("Shannon Entropy (bits/byte)")
    plt.ylabel("Number of Keys")
    plt.title("Distribution of Modulus Entropy")
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_nist_pass_rates(cmp):

    def calc_pass_rate(nist_list):
        total_tests = len(nist_list) * 6
        passed = 0
        for entry in nist_list:
            if entry["freq"]  >= 0.01: passed += 1
            if entry["block"] >= 0.01: passed += 1
            if entry["runs"]  >= 0.01: passed += 1
            if entry["lrun"]  >= 0.01: passed += 1
            if entry["apent"] >= 0.01: passed += 1
            if entry["chi"]   >= 0.01: passed += 1
        return (passed / total_tests) * 100

    rates = {
        "MT RNG": calc_pass_rate(cmp.stats["mt"]["nist"]),
        "OS RNG": calc_pass_rate(cmp.stats["os"]["nist"]),
        "EMN RNG": calc_pass_rate(cmp.stats["emn"]["nist"])
    }


    plt.figure(figsize=(8,6))
    plt.bar(rates.keys(), rates.values(), color=["blue","orange","green"])
    plt.ylabel("NIST Test Pass Rate (%)")
    plt.title("NIST SP 800-22 Test Pass Rate Comparison")
    plt.ylim(0,100)
    plt.tight_layout()
    plt.show()

def plot_chi_square_comparison(cmp):
    """Plot chi-square statistics for MT vs OS vs EMN"""
    mt_chi = [entry["chi_stat"] for entry in cmp.stats["mt"]["nist"]]
    os_chi = [entry["chi_stat"] for entry in cmp.stats["os"]["nist"]]
    emn_chi = [entry["chi_stat"] for entry in cmp.stats["emn"]["nist"]]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Chi-square statistics distribution
    ax1.hist(mt_chi, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax1.hist(os_chi, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax1.hist(emn_chi, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax1.axvline(255, color='black', linestyle='--', linewidth=1, label='Expected χ² (df=255)')
    ax1.set_xlabel("Chi-square Statistic (χ²)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Chi-square Test Statistics Distribution")
    ax1.legend()
    
    # P-values distribution
    mt_p = [entry["chi"] for entry in cmp.stats["mt"]["nist"]]
    os_p = [entry["chi"] for entry in cmp.stats["os"]["nist"]]
    emn_p = [entry["chi"] for entry in cmp.stats["emn"]["nist"]]

    
    ax2.hist(mt_p, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax2.hist(os_p, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax2.hist(emn_p, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax2.axvline(0.01, color='black', linestyle='--', linewidth=1, label='Significance Level (α=0.01)')
    ax2.set_xlabel("Chi-square P-value")
    ax2.set_ylabel("Frequency")
    ax2.set_title("Chi-square P-values Distribution")
    ax2.legend()
    
    plt.tight_layout()
    plt.show()

def plot_predictability_comparison(cmp):
    """Plot predictability (correlation coefficient) for baseline vs EMN"""
    mt_pred = cmp.stats["mt"]["predictability"]
    os_pred = cmp.stats["os"]["predictability"]
    emn_pred = cmp.stats["emn"]["predictability"]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Histogram of correlation coefficients
    ax1.hist(mt_pred, bins=20, alpha=0.6, label="MT RNG", color="blue")
    ax1.hist(os_pred, bins=20, alpha=0.6, label="OS RNG", color="orange")
    ax1.hist(emn_pred, bins=20, alpha=0.6, label="EMN RNG", color="green")
    ax1.axvline(0, color='black', linestyle='--', linewidth=1, label='r = 0 (no correlation)')
    ax1.set_xlabel("Correlation Coefficient (r)")
    ax1.set_ylabel("Frequency")
    ax1.set_title("Predictability: Correlation Between Successive Outputs")
    ax1.legend()
    
    # Box plot comparison
    ax2.boxplot([mt_pred, os_pred, emn_pred], 
                labels=["MT RNG", "OS RNG", "EMN RNG"],
                showmeans=True,
                patch_artist=True)
    ax2.axhline(0, color='black', linestyle='--', linewidth=1, alpha=0.5)
    ax2.set_ylabel("Correlation Coefficient (r)")
    ax2.set_title("Predictability Distribution Comparison")
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.show()

def analyze_implications(cmp):
    print("=== Phase 4: Implications Analysis ===")
    print("\nPython RNG Design:")
    for label in ["mt","os","emn"]:
        ents = cmp.stats[label]["ents"]
        avg_ent = sum(ents)/len(ents)
        print(f"* {label.upper()} average Shannon entropy: {avg_ent:.3f} bits/byte")
        if avg_ent < 7.5:
            print(f"  → {label.upper()} may be weak for cryptographic use in low-entropy environments")
        else:
            print(f"  → {label.upper()} performs reasonably well for cryptography")

    print("\nEmbedded Cryptographic Systems:")
    for label in ["mt","os","emn"]:
        mods = cmp.stats[label]["mods"]
        shared = 0
        for i in range(len(mods)):
            for j in range(i+1,len(mods)):
                if mods[i] != mods[j] and math.gcd(mods[i],mods[j]) > 1:
                    shared += 1
        if shared > 0:
            print(f"* {label.upper()} keys share factors: {shared} pairs → risk of factor attacks")
        else:
            print(f"* {label.upper()} keys share no factors → secure against factor attacks")

    print("\nFuture Entropy Management Strategies:")
    print("* Consider using entropy-mixing enhancements like EMN to improve randomness.")
    print("* Monitor NIST test pass rates to detect weak randomness early.")
    print("* Ensure proper seeding at startup in low-entropy environments.")
