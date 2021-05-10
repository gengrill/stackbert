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

### Drive

Drive Link: https://drive.google.com/drive/folders/1D2858mxjsNUXV-WIdqvuZNSzfO86ycwZ?usp=sharing

Notebook Link: https://colab.research.google.com/drive/1VVJz8L_GwsDFle-XHUsz5jFtS7CdXi26?usp=sharing

* Trained models are stored in `test_check`.
* `data-bin` replicates the `data-bin` on disk.

### Dataset

Compiler used: GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609

Dataset used for training is the same as [EKLAVYA](https://github.com/shensq04/EKLAVYA). Please find the raw binaries on ava at `/media/VMs/chinmay_dd/varRecovery/data/EKLAVYA/binary/x86`. Currently the models are trained on x86 binaries only since that is the target for BinRec 2.0.

SPEC 2017 binaries compiled with the same compiler can be found at : `/media/VMs/chinmay_dd/varRecovery/data/SPECDATA`
