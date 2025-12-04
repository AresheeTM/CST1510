import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import timedelta
from utils import load_csv


# =========================================
# TICKETS PAGE
# =========================================
page = st.query_params.get("page", "Tickets")

# =========================================
# SIMPLE TICKETS VIEW
# =========================================
if page == "Tickets":
    st.title("IT Tickets")

    tickets_df = load_csv("data/it_tickets.csv")   # FIXED PATH

    if tickets_df.empty:
        st.info("No ticket data found.")
    else:
        st.dataframe(tickets_df)

        if "status" in tickets_df.columns:
            st.subheader("Tickets by status")
            st.bar_chart(tickets_df["status"].value_counts())

# =========================================
# ADVANCED DASHBOARD
# =========================================
elif page == "Tickets Dashboard":   # ✅ FIXED
    st.title("IT Tickets — Analytics Dashboard")

    tickets_df = load_csv("data/it_tickets.csv")   # FIXED PATH

    if tickets_df.empty:
        st.info("No ticket data found.")

    else:
        # Normalize column references
        cols = {c.lower(): c for c in tickets_df.columns}

        def has(col): return col.lower() in cols
        def col(col): return cols.get(col.lower())

        status_col = col("status")
        priority_col = col("priority")
        assigned_col = col("assigned_to")
        desc_col = col("description")
        created_col = col("created_at")
        resolution_col = col("resolution_time_hours")

        # ----------------------------
        # SIDEBAR FILTERS
        # ----------------------------
        st.sidebar.header("Filter Tickets")

        filtered_df = tickets_df.copy()

        # Status filter
        if status_col:
            statuses = ["All"] + sorted(filtered_df[status_col].dropna().unique().astype(str))
            status_choice = st.sidebar.selectbox("Status", statuses)
            if status_choice != "All":
                filtered_df = filtered_df[filtered_df[status_col] == status_choice]

        # Priority filter
        if priority_col:
            priorities = ["All"] + sorted(filtered_df[priority_col].dropna().unique().astype(str))
            priority_choice = st.sidebar.selectbox("Priority", priorities)
            if priority_choice != "All":
                filtered_df = filtered_df[filtered_df[priority_col] == priority_choice]

        # Assigned-to filter
        if assigned_col:
            assigned_options = ["All"] + sorted(filtered_df[assigned_col].dropna().unique().astype(str))
            assigned_choice = st.sidebar.selectbox("Assigned To", assigned_options)
            if assigned_choice != "All":
                filtered_df = filtered_df[filtered_df[assigned_col] == assigned_choice]

        # Date range filter
        if created_col:
            filtered_df["_created_dt"] = pd.to_datetime(filtered_df[created_col], errors="coerce")
            min_date = filtered_df["_created_dt"].min()
            max_date = filtered_df["_created_dt"].max()

            if not pd.isna(min_date) and not pd.isna(max_date):
                date_range = st.sidebar.date_input("Created Date Range", (min_date, max_date))
                if len(date_range) == 2:
                    start_date, end_date = date_range
                    filtered_df = filtered_df[
                        (filtered_df["_created_dt"] >= pd.to_datetime(start_date)) &
                        (filtered_df["_created_dt"] <= pd.to_datetime(end_date))
                    ]

        # Keyword search
        if desc_col:
            keyword = st.sidebar.text_input("Search description")
            if keyword.strip():
                filtered_df = filtered_df[
                    filtered_df[desc_col].astype(str).str.contains(keyword, case=False, na=False)
                ]

        # Reset button
        if st.sidebar.button("Reset Filters"):
            st.rerun()

        # ----------------------------
        # DATA TABLE
        # ----------------------------
        with st.expander("Show Filtered Table"):
            st.dataframe(filtered_df)

        # ======================================================
        # KPIs
        # ======================================================
        total_tickets = len(filtered_df)

        status_series = filtered_df[status_col].astype(str).str.lower() if status_col else pd.Series([])
        open_count = (status_series.isin(["open", "in progress", "pending"])).sum()
        closed_count = (status_series.isin(["closed", "resolved"])).sum()

        avg_resolution = None
        if resolution_col:
            try:
                avg_resolution = filtered_df[resolution_col].astype(float).mean()
            except:
                avg_resolution = None

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Tickets", total_tickets)
        c2.metric("Open", open_count)
        c3.metric("Closed", closed_count)
        c4.metric("Avg Resolution (hrs)", f"{avg_resolution:.2f}" if avg_resolution else "N/A")

        st.markdown("---")

        # ======================================================
        # TWO COLUMN CHART
        # ======================================================
        left, right = st.columns(2)

        with left:
            if status_col:
                st.subheader("Tickets by Status")
                status_counts = filtered_df[status_col].value_counts().reset_index()
                status_counts.columns = ["status", "count"]
                fig_status = px.bar(status_counts, x="status", y="count", text="count")
                st.plotly_chart(fig_status, use_container_width=True)

            if priority_col and status_col and assigned_col:
                st.subheader("Priority → Status → Assigned")
                sun = filtered_df.groupby([priority_col, status_col, assigned_col]).size().reset_index(name="count")
                fig_sun = px.sunburst(sun, path=[priority_col, status_col, assigned_col], values="count")
                st.plotly_chart(fig_sun, use_container_width=True)

        with right:
            if priority_col:
                st.subheader("Priority Distribution")
                priority_counts = filtered_df[priority_col].value_counts().reset_index()
                priority_counts.columns = ["priority", "count"]
                fig_pri = px.pie(priority_counts, names="priority", values="count")
                st.plotly_chart(fig_pri, use_container_width=True)

            if resolution_col:
                st.subheader("Resolution Time Distribution")
                res = pd.to_numeric(filtered_df[resolution_col], errors="coerce").dropna()
                fig_res = px.histogram(res, nbins=20)
                st.plotly_chart(fig_res, use_container_width=True)

        st.markdown("---")

        # ======================================================
        # GANTT TIMELINE
        # ======================================================
        st.subheader("Ticket Timeline (Gantt View)")

        if created_col:
            gantt_df = filtered_df.copy()
            gantt_df["_start"] = pd.to_datetime(gantt_df[created_col], errors="coerce")

            if resolution_col:
                gantt_df["_dur"] = pd.to_numeric(gantt_df[resolution_col], errors="coerce").fillna(0)
                gantt_df["_finish"] = gantt_df["_start"] + gantt_df["_dur"].apply(
                    lambda x: timedelta(hours=float(x))
                )
            else:
                gantt_df["_finish"] = gantt_df["_start"]

            gantt_df["_task"] = gantt_df.index.astype(str)
            gantt_df = gantt_df.dropna(subset=["_start"])

            if not gantt_df.empty:
                fig_gantt = px.timeline(
                    gantt_df,
                    x_start="_start",
                    x_end="_finish",
                    y="_task",
                    color=priority_col if priority_col else status_col
                )
                fig_gantt.update_yaxes(autorange="reversed")
                st.plotly_chart(fig_gantt, use_container_width=True)
            else:
                st.info("Not enough date information for Gantt chart.")
