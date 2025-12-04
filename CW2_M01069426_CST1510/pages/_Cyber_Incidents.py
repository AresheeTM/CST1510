import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime
from utils import load_csv
 
# =========================================
# INCIDENTS PAGE
# =========================================
page = st.sidebar.selectbox("Select page", ["Incidents", "Cyber Incidents"])
if page == "Incidents":
    st.title("Cyber Incidents")

    # FIXED PATH
    incidents_df = load_csv("data/cyber_incidents.csv")

    if incidents_df.empty:
        st.info("No 'cyber_incidents.csv' found.")
    else:
        st.dataframe(incidents_df)

        numeric_cols = incidents_df.select_dtypes(include=['number']).columns
        if len(numeric_cols) > 0:
            st.subheader("Statistics")
            st.write(incidents_df[numeric_cols].describe())
        else:
            st.info("No numeric columns available.")


# -------------------------------
# Cyber Incidents Dashboard (Plotly)
# -------------------------------

elif page == "Cyber Incidents":
    st.title("Cyber Incidents — Dashboard")

    # FIXED PATH
    incidents_df = load_csv("data/cyber_incidents.csv")

    if incidents_df.empty:
        st.info("No cyber incidents data found.")
    else:
        cols = {c.lower(): c for c in incidents_df.columns}
        def has(c): return c.lower() in cols
        def col(c): return cols.get(c.lower())

        id_col = col("incident_id")
        ts_col = col("timestamp")
        sev_col = col("severity")
        cat_col = col("category")
        status_col = col("status")
        desc_col = col("description")

        # Sidebar filters
        st.sidebar.header("Filter incidents")
        df_f = incidents_df.copy()

        if sev_col:
            severities = ["All"] + sorted(df_f[sev_col].dropna().unique().astype(str))
            sev_choice = st.sidebar.selectbox("Severity", severities)
            if sev_choice != "All":
                df_f = df_f[df_f[sev_col] == sev_choice]

        if status_col:
            statuses = ["All"] + sorted(df_f[status_col].dropna().unique().astype(str))
            stat_choice = st.sidebar.selectbox("Status", statuses)
            if stat_choice != "All":
                df_f = df_f[df_f[status_col] == stat_choice]

        # Date range filter from timestamp
        if ts_col:
            df_f["_ts"] = pd.to_datetime(df_f[ts_col], errors="coerce")
            min_t = df_f["_ts"].min()
            max_t = df_f["_ts"].max()
            if not pd.isna(min_t) and not pd.isna(max_t):
                dr = st.sidebar.date_input("Incident date range", (min_t.date(), max_t.date()))
                if len(dr) == 2:
                    s, e = dr
                    df_f = df_f[(df_f["_ts"] >= pd.to_datetime(s)) & (df_f["_ts"] <= pd.to_datetime(e))]

        # Text search
        if desc_col:
            kw = st.sidebar.text_input("Search description (incidents)")
            if kw.strip():
                df_f = df_f[df_f[desc_col].astype(str).str.contains(kw, case=False, na=False)]

        if st.sidebar.button("Reset incidents filters"):
            st.experimental_rerun()

        # Show filtered table
        with st.expander("Show incidents table"):
            st.dataframe(df_f)

        # KPIs
        total_inc = len(df_f)
        open_inc = df_f[df_f[status_col].astype(str).str.lower().isin(["open","investigating","in progress"])] if status_col else pd.DataFrame()
        resolved_inc = df_f[df_f[status_col].astype(str).str.lower().isin(["resolved","closed"])] if status_col else pd.DataFrame()

        k1, k2, k3 = st.columns(3)
        k1.metric("Total incidents", f"{total_inc}")
        k2.metric("Open/Active", f"{len(open_inc)}")
        k3.metric("Resolved/Closed", f"{len(resolved_inc)}")

        st.markdown("---")

        # Two column charts
        left, right = st.columns(2)

        with left:
            # Incidents by severity
            if sev_col:
                st.subheader("Incidents by Severity")
                sev_counts = df_f[sev_col].fillna("Unknown").value_counts().reset_index()
                sev_counts.columns = ["severity", "count"]
                fig_sev = px.bar(sev_counts, x="severity", y="count", text="count", title="Severity distribution")
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.info("No 'severity' column found.")

            # Incidents by category
            if cat_col:
                st.subheader("Incidents by Category")
                cat_counts = df_f[cat_col].fillna("Unknown").value_counts().reset_index()
                cat_counts.columns = ["category", "count"]
                topn = st.slider("Top categories to show", min_value=3, max_value=20, value=10)
                fig_cat = px.bar(cat_counts.head(topn), x="category", y="count", text="count", title="Top categories")
                fig_cat.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig_cat, use_container_width=True)
            else:
                st.info("No 'category' column found.")

        with right:
            # Timeline
            if ts_col:
                st.subheader("Incidents over time")
                df_time = df_f.copy()
                df_time["_ts"] = pd.to_datetime(df_time[ts_col], errors="coerce")
                df_time = df_time.dropna(subset=["_ts"])
                if not df_time.empty:
                    df_time["_date"] = df_time["_ts"].dt.date
                    times = df_time.groupby("_date").size().reset_index(name="count")
                    fig_time = px.line(times, x="_date", y="count", title="Incidents per day")
                    st.plotly_chart(fig_time, use_container_width=True)
                else:
                    st.info("No datetime values to plot timeline.")

            # Status donut
            if status_col:
                st.subheader("Status distribution")
                status_counts = df_f[status_col].fillna("Unknown").value_counts().reset_index()
                status_counts.columns = ["status", "count"]
                fig_status = px.pie(status_counts, names="status", values="count", title="Incident status")
                st.plotly_chart(fig_status, use_container_width=True)

        st.markdown("---")

        # Details selector
        st.subheader("Incident details")
        if id_col:
            sel = st.selectbox("Select incident id", ["None"] + sorted(df_f[id_col].dropna().astype(str).unique().tolist()))
            if sel and sel != "None":
                detail = df_f[df_f[id_col].astype(str) == sel].iloc[0].to_dict()
                st.json(detail)
        else:
            st.info("No incident id column to enable quick selection.")
