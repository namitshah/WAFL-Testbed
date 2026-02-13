# WAFL-Testbed
A repository for testbed implementations of WAFL projects. <br/>
An extension of the [WAFL-Testbed](https://github.com/jo2lxq/wafl/tree/testbed-develop/WAFL-Testbed) project (WAFL-MLP implementation).<br/>
Also, please refer to the UTokyo [WAFL repository](https://github.com/jo2lxq/wafl).
### Modify the **Vanilla** Project's code (generalized minimal implementation) <br/> for deploying and testing any WAFL variant.
## Common Project Structure:
  - ctrl/
    - execution_config, parameters.json, deploy.sh, main.py, collect.py, analyze.py
  - wafl/
    - config/ (common/ and ID/)
      - config.json [*]
    - dataset/ (common/ and ID/)
      - dataset files
    - src/ (common/ and ID/)
      - main.py
  - utils/
    - contact_pattern/
      - contact pattern files (json)
    - supplementary resources
  - results/
    - experiment results [*]
  - uv.lock, pyproject.toml, miscellaneous resources
#### [*] Auto-Generated during deployment.
## Common Experiment Flow
1. Prepare the project's source code, datasets, contact pattern files, etc.
2. Specify the principal configuration (execution_config, parameters.json).
3. Remotely log into the target Control Server (ssh).
4. Upload the project's source code onto the system.
5. Generate and activate the virtual environment with uv sync (from pyproject.toml and uv.lock).
6. Deploy the project to the Execution Servers (ctrl/deploy.sh).
7. Start the Experiment Run (python ctrl/main.py).
8. Collect the results after completion (python ctrl/collect.py).
9. Analyze and visualize the results (python ctrl/analyze.py).
## WAFL Testbed | IEEE Xplore
Namit Shah, Kosei Takahashi, Tatsumi Yamazaki, Natsuki Zenko, Hiroshi Esaki, Hideya Ochiai, <br/>
**An Emulation Platform for Wireless Ad Hoc Federated Learning: Design, Implementation, and Case Study**, <br/>
2026 IEEE International Conference on Knowledge: Science and Technology [(IEEE Xplore)]().
