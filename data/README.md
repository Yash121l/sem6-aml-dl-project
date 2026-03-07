# Dataset — CICIDS-2017

## Why data is not in this repository

The CICIDS-2017 dataset is **not committed to git** for two reasons:

1. **File size**: The full dataset is ~800 MB of CSV files, making it impractical
   to version in a standard git repository.  Even with Git LFS the large binaries
   would bloat clone times for every user.

2. **License**: The dataset is provided for research purposes by the Canadian
   Institute for Cybersecurity.  Redistribution in a public repository would
   violate the dataset's terms of use.

## Download Instructions

1. Navigate to the official dataset page:
   **https://www.unb.ca/cic/datasets/ids-2017.html**

2. Register or agree to the terms of use.

3. Download all CSV files.  You will receive a set of files named by day, e.g.:
   - `Monday-WorkingHours.pcap_ISCX.csv`
   - `Tuesday-WorkingHours.pcap_ISCX.csv`
   - `Wednesday-workingHours.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
   - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
   - `Friday-WorkingHours-Morning.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

4. Place all CSVs in `data/CICIDS2017/`:
   ```
   data/
   └── CICIDS2017/
       ├── Monday-WorkingHours.pcap_ISCX.csv
       ├── Tuesday-WorkingHours.pcap_ISCX.csv
       ├── ...
   ```

5. The notebooks expect files in exactly this location.
   `Stage 1 EDA` (`notebooks/01_EDA.ipynb`) will load them automatically.

## Dataset Statistics

| Property | Value |
|----------|-------|
| Total flows | ~2.8 million |
| Features (raw) | 80 |
| Attack types | 14 |
| Benign flows | ~2.3 million |
| Attack flows | ~0.5 million |
| Collection period | Monday–Friday, July 3–7, 2017 |

## Known Data Quality Issues

- Several features contain **infinite values** (`np.inf`) produced by zero-division
  in the feature extractor (CICFlowMeter).  These are handled in Stage 2
  preprocessing by replacing them with column medians.
- Extreme **class imbalance**: benign traffic accounts for ~82% of all flows.
  This motivates our one-class (benign-only) training strategy.
- A small number of **duplicate rows** exist and are removed during EDA.

## Citation

If you use this dataset, please cite:

> Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).
> Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
> Characterization. *Proceedings of the 4th International Conference on
> Information Systems Security and Privacy (ICISSP)*, pp. 108–116.
