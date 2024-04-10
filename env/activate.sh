#!/bin/bash
echo Setting up Virtual Environment...
VENV_NAME=.venv-wrapmaster
python -m venv $VENV_NAME
source $VENV_NAME/bin/activate && pip install pip==24.0 && pip install -r env/requirements.txt
