import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime

# Correct import for your custom loader
from utils import load_csv


# =========================================
# DATASETS PAGE
# =========================================

page = st.session_state.get("page", "Datasets")

# =========================================================
# SIMPLE TABLE VIEW  (Page 1)
# =========================================================
if page == "Datasets":
    st.title("Datasets")

    datasets_df = load_csv("data/datasets_metadata.csv")   # FIXED PATH

    if datasets_df.empty:
        st.info("No dataset metadata found.")
    else:
        st.dataframe(datasets_df)

        if "name" in datasets_df.columns:
            st.subheader("Datasets by Name")
            st.bar_chart(datasets_df["name"].value_counts())

        if "uploaded_by" in datasets_df.columns:
            st.subheader("Uploads by User")
            st.bar_chart(datasets_df["uploaded_by"].value_counts())

        if "rows" in datasets_df.columns:
            st.subheader("Rows Distribution")
            st.bar_chart(datasets_df["rows"])


# =========================================================
# METADATA DASHBOARD (Page 2)  
# =========================================================
elif page == "Datasets Dashboard":
    st.title("Datasets — Metadata Dashboard")

    datasets_df = load_csv("data/datasets_metadata.csv")   # FIXED PATH

    if datasets_df.empty:
        st.info("No dataset metadata found.")
    else:
        # Normalize column lookup
        cols = {c.lower(): c for c in datasets_df.columns}
        def has(c): return c.lower() in cols
        def col(c): return cols.get(c.lower())

        name_col = col("name")
        rows_col = col("rows")
        cols_col = col("columns")
        uploader_col = col("uploaded_by")
        upload_date_col = col("upload_date")
        dataset_id_col = col("dataset_id") or col("id")

        # ------------ Sidebar Filters ------------

        st.sidebar.header("Filter datasets")
        df_f = datasets_df.copy()

        # Filter uploader
        if uploader_col:
            uploaders = ["All"] + sorted(df_f[uploader_col].dropna().unique().astype(str))
            up_choice = st.sidebar.selectbox("Uploaded by", uploaders)
            if up_choice != "All":
                df_f = df_f[df_f[uploader_col] == up_choice]

        # Filter by upload date
        if upload_date_col:
            df_f["_udt"] = pd.to_datetime(df_f[upload_date_col], errors="coerce")
            min_d = df_f["_udt"].min()
            max_d = df_f["_udt"].max()
            if not pd.isna(min_d) and not pd.isna(max_d):
                rng = st.sidebar.date_input("Upload date range", (min_d.date(), max_d.date()))
                if len(rng) == 2:
                    start, end = rng
                    df_f = df_f[(df_f["_udt"] >= pd.to_datetime(start)) & (df_f["_udt"] <= pd.to_datetime(end))]

        # Keyword search
        if name_col:
            kw = st.sidebar.text_input("Search dataset name")
            if kw.strip():
                df_f = df_f[df_f[name_col].astype(str).str.contains(kw, case=False, na=False)]

        # Reset button
        if st.sidebar.button("Reset dataset filters"):
            st.experimental_rerun()

        # ------------ Table ------------
        with st.expander("Show datasets table"):
            st.dataframe(df_f)

        # ------------ KPIs ------------
        total = len(df_f)
        total_rows = df_f[rows_col].dropna().astype(float).sum() if rows_col else None
        avg_rows = df_f[rows_col].dropna().astype(float).mean() if rows_col else None

        k1, k2, k3 = st.columns(3)
        k1.metric("Total datasets", f"{total}")
        k2.metric("Total rows (sum)", f"{int(total_rows):,}" if total_rows else "N/A")
        k3.metric("Avg rows per dataset", f"{avg_rows:.2f}" if avg_rows else "N/A")

        st.markdown("---")

        left, right = st.columns(2)

        # ------------ Left charts ------------
        with left:
            if uploader_col:
                st.subheader("Uploads by user")
                uploader_counts = df_f[uploader_col].fillna("Unknown").astype(str).value_counts().reset_index()
                uploader_counts.columns = ["uploader", "count"]
                fig_up = px.bar(uploader_counts, x="uploader", y="count", text="count")
                st.plotly_chart(fig_up, use_container_width=True)

            if rows_col and name_col:
                st.subheader("Top datasets by rows")
                topn = st.slider("Top N", 3, 20, 10)
                top_df = df_f[[name_col, rows_col]].dropna().astype({rows_col: float}).sort_values(by=rows_col, ascending=False).head(topn)
                fig_top = px.bar(top_df, x=name_col, y=rows_col, text=rows_col)
                st.plotly_chart(fig_top, use_container_width=True)

        # ------------ Right charts ------------
        with right:
            if rows_col:
                st.subheader("Rows distribution")
                rows_series = pd.to_numeric(df_f[rows_col], errors="coerce").dropna()
                if not rows_series.empty:
                    fig_rows = px.histogram(rows_series, nbins=30)
                    st.plotly_chart(fig_rows, use_container_width=True)

            if cols_col:
                st.subheader("Columns distribution")
                cols_series = pd.to_numeric(df_f[cols_col], errors="coerce").dropna()
                if not cols_series.empty:
                    fig_cols = px.histogram(cols_series, nbins=20)
                    st.plotly_chart(fig_cols, use_container_width=True)

        st.markdown("---")

        # Scatter chart
        if rows_col and cols_col:
            st.subheader("Rows vs Columns")
            scatter_df = df_f[[name_col, rows_col, cols_col]].dropna()
            scatter_df[rows_col] = pd.to_numeric(scatter_df[rows_col], errors="coerce")
            scatter_df[cols_col] = pd.to_numeric(scatter_df[cols_col], errors="coerce")
            fig_sc = px.scatter(scatter_df, x=cols_col, y=rows_col, hover_data=[name_col])
            st.plotly_chart(fig_sc, use_container_width=True)
