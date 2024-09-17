# Reproduction Package
- `evaluation_code.tar.gz` - Download from [Zenodo](https://zenodo.org/records/13332863) 
    - Contains the evaluation code  `fuzzing-analysis` used to build the Docker container and perform experiments either from scratch or reproduce results as presented in the CCS'24 paper.

# Docker image setup

## Install Docker

- Install docker by following instructions for Ubuntu [here](https://docs.docker.com/engine/install/ubuntu/)
- After installation, configure Docker to make it run as a non-root user using instructions [here](https://docs.docker.com/engine/install/linux-postinstall/)

## Pull our image from dockerhub
```
docker pull adamstorek/fox:latest
```

## Run

```
# Create image in dameon mode with the name "optfuzz_eval"
docker run --privileged --network='host' -d --name="optfuzz_eval" -it adamstorek/fox:latest
docker exec -it optfuzz_eval /bin/bash
```

# Reproducing Paper's Claims

## 1. From Existing Results
To reproduce our results from within the docker container, read the following instructions.

### A. Generate all paper's assets - tables and figures - except the bug discovery evaluation results on Magma:
```
cd /workspace/fuzzopt-eval/fuzzdeployment/process_results
python generate_assets.py
```
All paper's assets can now be found in the `/workspace/fuzzopt-eval/fuzzdeployment/process_results/paper_assets` directory, labeled accordingly (e.g. Table 3 is labeled as `Table 3.txt`, Figure 2 as `Figure 2.pdf`):

- Figure 2 on page 9: `paper_assets/Figure\ 2.pdf`
- Table 3 on page 10: `paper_assets/Table\ 3.txt`
- Table 4 on page 10: `paper_assets/Table\ 4.txt`
- Figure 3 on page 12: `paper_assets/Figure\ 2.pdf`
- Table 7 on page 12: `paper_assets/Table\ 7.txt`
- Table 8 on page 12: `paper_assets/Table\ 8.txt`
- Table 9 on page 12: `paper_assets/Table\ 9.txt`

### B. To generate Table 5 on page 11 showcasing the bug discovery evaluation results on Magma, follow these instructions below **outside of the spawned docker container** on your host machine:
  - Decompress the archive `evaluation_code.tar.gz`.
  - Navigate to `fuzzing-analysis/fuzzdeployment/magma_artifact` 
  - Run the following commands:
  ```
  python -m venv magma_eval
  source ./magma_eval/bin/activate
  pip install -r requirements.txt
  python handle.py full_timing.json 
  ```

## 2. Generate New Results
Running the entire gamut of coverage experiments as done in the paper (38 targets x 5 fuzzers x 5 campaigns x 24 hours) will require a non-trivial amount of resources. Consequently, we provided a limited version of the experiment (6 targets (3 FuzzBench and 3 standalone) x 5 fuzzers x 3 campaigns x 20 minutes) that can be run on regular, consumer-grade hardware (16 core cpu) within 2 hours to showcase the trend we observe in the paper. Furthermore, we provided a limited version of the experiment which contains all targets. Please replace `./set_limited_targets.sh` with `./set_all_targets.sh` to run a limited version of the experiment across all targets.

### A. Build the necessary targets
```
cd /workspace/fuzzopt-eval/fuzzdeployment/targets
./unzip_seeds.sh
./set_limited_targets.sh
```

### B. Deploy the limited evaluation run
First navigate into the `scripts` directory and spawn a `beanstalk` server as follows:
```
cd /workspace/fuzzopt-eval/fuzzdeployment/scripts
beanstalkd &
```

The parameter `-n` used by `create_fuzz_script.py` below controls the number of cores that the experiment can use (the number of fuzzing jobs that can run in parallel). We assume at least a 16-core machine, hence we set `-n 16`. Nevertheless, if fewer cores are present, please modify `-n` to reflect this (e.g. for a 4-core machine, set `-n 4`). Please replace `limited.config.json` with `limited_all.config.json` to run a limited version of the experiment across all targets.

```
python create_fuzz_script.py -c limited.config.json -n 16 --flush
python create_fuzz_script.py -c limited.config.json -n 16 --flush
python create_fuzz_script.py -c limited.config.json -n 16 --flush
python create_fuzz_script.py -c limited.config.json -n 16 --put
screen -S deployment -dm python create_fuzz_script.py -c limited.config.json -n 16 --get
```

### C. After the runs have completed (in ~2.5 hours on a 16-core machine):
```
cd /workspace/fuzzopt-eval/fuzzdeployment/process_results
python parse_results.py --raw_data ../results --cov --out ./results/limited
python generate_assets.py --limited --inp ./results/limited
```

The coverage tables can now be found in the `paper_assets_limited` directory, labeled accordingly:

- Table 3 (FuzzBench coverage) on page 10: `paper_assets/Table\ 3.txt`
- Table 4 (Standalone coverage) on page 10: `paper_assets/Table\ 4.txt`


## D. Run the ground truth bug discovery experiment on Magma from scratch (1 hour on 16-core machine)

Running the entire gamut of Magma experiments as done in the paper (17 targets x 5 fuzzers x 5 campaigns x 24 hours) will require a non-trivial amount of resources. Consequently, we provided a limited version of the experiment (3 targets x 5 fuzzers x 3 campaigns x 20 minutes) to showcase the trend we observe in the paper.

To run this experiment and create tabulated results same as Table 5 follow the below set of commands **outside of docker on your host machine**:
- Decompress the archive `evaluation_code.tar.gz`.
- Navigate to `fuzzing-analysis/fuzzdeployment/magma_artifact`
- Run `./setup_and_run_magma.sh` 

The above script will perform the following set of actions:
- Clones the magma repository
- Integrates the fuzzers that were evaluated as part of the bug discovery experiment (FOX, AFLPP, AFLPP+C, FOX+D, and AFLPP+CD)
- Runs campaigns for three targets (tiffcp, libpng, and libxml2_xml) as per the configuration specified above.
- Generates raw timing results from Magma and then processes it to create the tabulation of bugs uncovered in each of these targets by the fuzzers

If you'd like to run all targets under the limited configuration (17 targets x 5 fuzzers x 3 campaigns x 20 minutes) then follow the below instructions (assuming you've already decompressed the evaluation_code.tar.gz):
- Navigate to `fuzzing-analysis/fuzzdeployment/magma_artifact`
- Run `./setup_and_run_magma_full.sh` 

# Notes on reusability
The artifact can be easily extended to evaluate other targets.

## Adding a new target
To add a new target to the evaluation, one can follow this procedure:
1. Add a new target directory to `/workspace/fuzzopt-eval/fuzzdeployment/targets`.
    - Add a `preinstall.sh` script that allows downloads the target's source code and installs any necessary dependencies.
    - Add a `build_aflpp.sh` script that takes as argument one of the following:
        - `aflpp` that builds the target for AFLplusplus without cmplog using the `/workspace/AFLplusplus/afl-clang-fast[++]` compiler
        - `cmplog` that builds the target for AFLplusplus with cmplog using the `/workspace/AFLplusplus/afl-clang-fast[++]` compiler
        - `optfuzz_nogllvm` that builds the target for FOX using the `/workspace/OptFuzzer/afl-clang-fast[++]` and then runs `/workspace/OptFuzzer/gen_graph_no_gllvm_15.py [target_name] instrument_meta_data` to generate the necessary metadata for FOX to run.
2. Add the target name to `/workspace/fuzzopt-eval/fuzzdeployment/targets/set_limited_target.sh`.
3. Add a run configuration file including each desired mode (`baseline`, `cmplog`, `cmplog_dict`, `optfuzz`, or `optfuzz_dict`) and append it to `limited.config.json`. One can use one of the other config files in that directory as a starter and modify only the path to the target(s), path to the seed inputs, (optional) path to dictionaries, and path to output. 
4. Add the target name to:
- `/workspace/fuzzopt-eval/fuzzdeployment/process_results/parse_results.py`
- `/workspace/fuzzopt-eval/fuzzdeployment/process_results/generate_assets.py`

## Adding an existing target to the limited run
An existing target is already setup everywhere and it is only necessary to append its existing configuration file available in `/workspace/fuzzopt-eval/fuzzdeployment/scripts/fuzz-configs/full_configs` to `/workspace/fuzzopt-eval/fuzzdeployment/scripts/limited.config.json`, potentially updating the previous configuration's `jobcount` and `fuzztimeout` parameters to correspond to the number of runs and run duration, respectively.
