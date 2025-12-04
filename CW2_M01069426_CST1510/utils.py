# =========================================================
# utils.py - Shared helper functions for the Streamlit app
# Author: Areshee Marimootoo (M01069426)
# Multi-Domain Intelligence Platform
# =========================================================

import os
import pandas as pd
import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_csv(file_name):
    """
    Safely loads CSV from the data folder with fallback and error messaging.
    """
    # Build full path
    full_path = os.path.join(BASE_DIR, file_name)

    # Debug print
    if not os.path.exists(full_path):
        st.warning(f"[utils] File not found: {full_path}")
        return pd.DataFrame()

    try:
        return pd.read_csv(full_path)
    except Exception as e:
        st.error(f"[utils] Error loading CSV: {e}")
        return pd.DataFrame()


