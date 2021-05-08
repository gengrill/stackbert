Machine Learning for Runtime Stack Size Estimation
---

### Code

Experiments can be replicated using the workflow detailed below.

### Workflow

* Run the `mainDriver.py` script to collect stack output for individual binaries. The output of this stage is a folder with an output json for each analyzed binary.
```
{
  "func_name": {
                "inp" : "55 89 ..." <function disassembly>
                "out" : [4,4,4,5...] <stack layout as discerned by stacksyms
               },
   ....
}
```
* Run `dataresolver.py` to collect all data in a single json and remove duplicate functions.
* Run `dataProcessing.py` to binarize data and store it in the form which can be consumed by fairseq. Please edit constants at the top of the code appropriately.
* Create a virtual environment and install pytoch/fairseq. `pip install fairseq` should work just fine.
* Run `fairseq/scripts/pretrain/preprocess.sh` to binarize training data for pretraining task. Please edit paths in the script.
* Run `faiseq/scripts/finetune/preprocess.sh` to binarize training data for finetuning (classification) task. Please edit paths in the scripts.
* Upload generated data in the `data-bin` folder to the `data-bin` folder in the shared drive to use for training.

### Dataset

Dataset used is the same as [EKLAVYA](https://github.com/shensq04/EKLAVYA). Please find it on ava at `/media/VMs/chinmay_dd/varRecovery/otherProjects/EKLAVYA/binary/`. Currently the models are trained on x86 binaries only since that is the target for BinRec 2.0.
