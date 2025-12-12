import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime
from utils import load_csv, create_simple_pdf
import streamlit.components.v1 as components
from ai_chatbot import dashboard_chat
from ai_sidebar import ai_sidebar

# ============================
# DEFINE CURRENT PAGE
# ============================
current_page = "Cyber Incidents"
st.session_state.current_page = current_page  # Optional, if used elsewhere

# ============================
# CUSTOM NEON PINK + BLACK STYLING
# ============================
st.markdown("""
    <style>
    /* App background & text */
    .stApp {
        background-color: #0a0a0a;
        color: #ff69b4;
        font-family: 'Courier New', monospace;
    }

    /* Centered Title */
    .dashboard-title {
        text-align: center;
        font-size: 3em;
        font-weight: bold;
        color: #ff69b4;
        text-shadow: 0 0 10px #ff69b4, 0 0 20px #ff69b4;
        margin-bottom: 10px;
    }

    /* Streamlit metric styling for neon */
    .stMetric label {color: #ff69b4;}
    .stMetric div[data-testid="stMetricValue"] {color: #ff69b4;}
    </style>
""", unsafe_allow_html=True)

# ============================
# TITLE
# ============================
st.markdown('<div class="dashboard-title">CYBER INCIDENTS — DASHBOARD</div>', unsafe_allow_html=True)

# ============================
# DRAGGABLE INTERACTIVE NEON CONSTELLATION PANEL WITH TOGGLE
# ============================
toggle_constellation = st.checkbox("Show Neon Star Constellation ✨", value=True)

if toggle_constellation:
    components.html("""
    <style>
    .glass-panel {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 20px;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        padding: 0;
        margin: 10px auto;
        border: 2px solid rgba(255, 105, 180, 0.5);
        text-align: center;
        max-width: 90%;
        height: 260px;
        position: relative;
        overflow: hidden;
        box-shadow: 0 8px 30px rgba(255, 105, 180, 0.4), 0 0 50px rgba(255, 105, 180, 0.3) inset;
        cursor: grab;
    }
    canvas {position: absolute; top:0; left:0;}
    </style>

    <div class="glass-panel" id="glass-panel"></div>
    <canvas id="constellation-canvas"></canvas>

    <script>
    const panel = document.getElementById("glass-panel");
    const canvas = document.getElementById("constellation-canvas");
    canvas.width = panel.offsetWidth;
    canvas.height = panel.offsetHeight;
    const ctx = canvas.getContext("2d");

    const stars = [];
    const numStars = 60;
    const maxDist = 80;
    const particles = [];
    const trailParticles = [];
    let mouse = {x: canvas.width/2, y: canvas.height/2};
    let offset = {x:0, y:0};
    let isDragging = false;
    let dragStart = {x:0, y:0};

    function randomParallax() { return 0.01 + Math.random()*0.03; }

    for(let i=0;i<numStars;i++){
        stars.push({
            x: Math.random()*canvas.width,
            y: Math.random()*canvas.height,
            radius: 1.5 + Math.random()*1.5,
            parallax: randomParallax(),
            twinkle: Math.random()*1.0
        });
    }

    class Particle {
        constructor(x,y){
            this.x=x; this.y=y;
            this.vx=(Math.random()-0.5)*2;
            this.vy=(Math.random()-0.5)*2;
            this.life=1.0;
        }
        update(){ this.x+=this.vx; this.y+=this.vy; this.life-=0.02; return this.life>0;}
    }

    class TrailParticle {
        constructor(x,y){
            this.x = x; this.y = y;
            this.life = 1.0;
        }
        update(){ this.life -= 0.03; return this.life>0;}
    }

    panel.addEventListener('mousedown', e=>{
        isDragging = true;
        dragStart.x = e.clientX - offset.x;
        dragStart.y = e.clientY - offset.y;
        panel.style.cursor = "grabbing";
    });

    document.addEventListener('mouseup', e=>{
        isDragging = false;
        panel.style.cursor = "grab";
    });

    document.addEventListener('mousemove', e=>{
        if(isDragging){
            offset.x = e.clientX - dragStart.x;
            offset.y = e.clientY - dragStart.y;
            panel.style.transform = `translate(${offset.x}px, ${offset.y}px)`;
        }

        const rect = panel.getBoundingClientRect();
        mouse.x = e.clientX - rect.left;
        mouse.y = e.clientY - rect.top;

        for(let i=0;i<2;i++){
            particles.push(new Particle(mouse.x, mouse.y));
            trailParticles.push(new TrailParticle(mouse.x, mouse.y));
        }
    });

    function draw(){
        ctx.clearRect(0,0,canvas.width,canvas.height);

        // draw lines between stars
        ctx.strokeStyle = "rgba(255,105,180,0.3)";
        ctx.lineWidth = 1;
        for(let i=0;i<stars.length;i++){
            for(let j=i+1;j<stars.length;j++){
                const dx = stars[i].x - stars[j].x;
                const dy = stars[i].y - stars[j].y;
                const dist = Math.sqrt(dx*dx + dy*dy);
                if(dist<maxDist){
                    ctx.beginPath();
                    ctx.moveTo(stars[i].x, stars[i].y);
                    ctx.lineTo(stars[j].x, stars[j].y);
                    ctx.stroke();
                }
            }
        }

        // draw stars (no shrinking)
        stars.forEach(star=>{
            star.twinkle = (star.twinkle+0.02)%1.0;
            const opacity = 0.5 + 0.5*Math.sin(star.twinkle*Math.PI*2);
            ctx.beginPath();
            ctx.arc(star.x, star.y, star.radius, 0, Math.PI*2);
            ctx.fillStyle = `rgba(255,105,180,${opacity})`;
            ctx.fill();
        });

        // draw particle effects
        for(let i=particles.length-1;i>=0;i--){
            const p = particles[i];
            ctx.beginPath();
            ctx.arc(p.x,p.y,2,0,Math.PI*2);
            ctx.fillStyle=`rgba(255,105,180,${p.life})`;
            ctx.fill();
            if(!p.update()){particles.splice(i,1);}
        }

        // draw trail particles
        for(let i=trailParticles.length-1;i>=0;i--){
            const t = trailParticles[i];
            ctx.beginPath();
            ctx.arc(t.x, t.y, 4, 0, Math.PI*2);
            ctx.fillStyle = `rgba(255,182,193,${t.life})`;
            ctx.fill();
            if(!t.update()){trailParticles.splice(i,1);}
        }

        requestAnimationFrame(draw);
    }
    draw();
    </script>
    """, height=280)

# ============================
# CYBER INCIDENTS DASHBOARD CODE
# ============================

# Load CSV
incidents_df = load_csv("data/cyber_incidents.csv")

if incidents_df.empty:
    st.info("No cyber incidents data found.")
else:
    # Column mapping
    cols = {c.lower(): c for c in incidents_df.columns}
    def col(c): return cols.get(c.lower())

    id_col = col("incident_id")
    ts_col = col("timestamp")
    sev_col = col("severity")
    cat_col = col("category")
    status_col = col("status")
    desc_col = col("description")
    reporter_col = col("reported_by")  # optional

    # -------------------------
    # Sidebar Filters
    # -------------------------
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

    # Date range filter
    if ts_col:
        df_f["_ts"] = pd.to_datetime(df_f[ts_col], errors="coerce")
        min_t, max_t = df_f["_ts"].min(), df_f["_ts"].max()
        if not pd.isna(min_t) and not pd.isna(max_t):
            dr = st.sidebar.date_input("Incident date range", (min_t.date(), max_t.date()))
            if len(dr) == 2:
                s, e = dr
                df_f = df_f[(df_f["_ts"] >= pd.to_datetime(s)) & (df_f["_ts"] <= pd.to_datetime(e))]

    # Text search
    if desc_col:
        kw = st.sidebar.text_input("Search description")
        if kw.strip():
            df_f = df_f[df_f[desc_col].astype(str).str.contains(kw, case=False, na=False)]

    if st.sidebar.button("Reset filters"):
        st.experimental_rerun()

    # -------------------------
    # KPIs
    # -------------------------
    total_inc = len(df_f)
    open_inc = df_f[df_f[status_col].astype(str).str.lower().isin(["open","investigating","in progress"])] if status_col else pd.DataFrame()
    resolved_inc = df_f[df_f[status_col].astype(str).str.lower().isin(["resolved","closed"])] if status_col else pd.DataFrame()

    k1, k2, k3 = st.columns(3)
    k1.metric("Total Incidents", total_inc)
    k2.metric("Open/Active", len(open_inc))
    k3.metric("Resolved/Closed", len(resolved_inc))
    st.markdown("---")

    # -------------------------
    # Dashboard Charts
    # -------------------------
    left1, right1 = st.columns(2)

    with left1:
        # Incidents by Severity
        if sev_col:
            st.subheader("Incidents by Severity")
            sev_counts = df_f[sev_col].fillna("Unknown").value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig_sev = px.bar(sev_counts, x="severity", y="count", text="count",
                             color="severity", color_discrete_sequence=px.colors.sequential.Plasma,
                             title="Severity Distribution")
            st.plotly_chart(fig_sev, use_container_width=True)

        # Incidents by Category
        if cat_col:
            st.subheader("Incidents by Category")
            cat_counts = df_f[cat_col].fillna("Unknown").value_counts().reset_index()
            cat_counts.columns = ["category", "count"]
            topn = st.slider("Top categories to show", 3, 20, 10)
            fig_cat = px.bar(cat_counts.head(topn), x="category", y="count", text="count",
                             title="Top Categories",
                             color=cat_counts.head(topn)["count"],
                             color_continuous_scale=px.colors.sequential.Viridis)
            fig_cat.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_cat, use_container_width=True)

        # Severity vs Status Heatmap
        if sev_col and status_col:
            st.subheader("Severity vs Status Heatmap")
            heat_df = df_f.groupby([sev_col, status_col]).size().reset_index(name="count")
            fig_heat = px.density_heatmap(heat_df, x=status_col, y=sev_col, z="count",
                                          color_continuous_scale="Viridis",
                                          title="Severity vs Status")
            st.plotly_chart(fig_heat, use_container_width=True)

    with right1:
        # Timeline
        if ts_col:
            st.subheader("Incidents Over Time")
            df_time = df_f.dropna(subset=[ts_col])
            df_time["_date"] = pd.to_datetime(df_time[ts_col]).dt.date
            times = df_time.groupby("_date").size().reset_index(name="count")
            fig_time = px.line(times, x="_date", y="count", title="Incidents Per Day")
            st.plotly_chart(fig_time, use_container_width=True)

        # Status Distribution
        if status_col:
            st.subheader("Status Distribution")
            df_f["_status_color"] = np.where(df_f[status_col].str.lower().isin(["open","investigating","in progress"]),
                                             "Open/Active","Resolved/Closed")
            status_counts = df_f["_status_color"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig_status = px.pie(status_counts, names="status", values="count",
                                color="status",
                                color_discrete_map={"Open/Active": "red", "Resolved/Closed": "green"},
                                title="Incident Status")
            st.plotly_chart(fig_status, use_container_width=True)

        # Category vs Status stacked bar
        if cat_col and status_col:
            st.subheader("Category vs Status")
            stacked = df_f.groupby([cat_col, "_status_color"]).size().reset_index(name="count")
            fig_stack = px.bar(stacked, x=cat_col, y="count", color="_status_color",
                               text="count", title="Category vs Status",
                               color_discrete_map={"Open/Active": "red", "Resolved/Closed": "green"})
            fig_stack.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_stack, use_container_width=True)

    # -------------------------
    # Bottom Charts
    # -------------------------
    st.markdown("---")
    bottom1, bottom2 = st.columns(2)

    with bottom1:
        # Incidents by Hour
        if ts_col:
            st.subheader("Incidents by Hour")
            df_hour = df_f.copy()
            df_hour["_hour"] = pd.to_datetime(df_hour[ts_col]).dt.hour
            hour_counts = df_hour["_hour"].value_counts().sort_index().reset_index()
            hour_counts.columns = ["hour", "count"]
            fig_hour = px.bar(hour_counts, x="hour", y="count", text="count", title="Incidents by Hour")
            st.plotly_chart(fig_hour, use_container_width=True)

        # Top Reporters
        if reporter_col:
            st.subheader("Top Reporters")
            top_rep = df_f[reporter_col].fillna("Unknown").value_counts().head(10).reset_index()
            top_rep.columns = ["reporter", "count"]
            fig_rep = px.bar(top_rep, x="reporter", y="count", text="count", title="Top Reporters")
            fig_rep.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_rep, use_container_width=True)

    with bottom2:
        # Numeric stats (if any)
        numeric_cols = df_f.select_dtypes(include=['number']).columns
        if len(numeric_cols) > 0:
            st.subheader("Numeric Statistics")
            st.write(df_f[numeric_cols].describe())

        # Show table
        with st.expander("Show Incidents Table"):
            st.dataframe(df_f)

    # -------------------------
    # Details selector
    # -------------------------
    st.markdown("---")
    st.subheader("Incident Details")
    if id_col:
        sel = st.selectbox("Select incident ID", ["None"] + sorted(df_f[id_col].dropna().astype(str).unique().tolist()))
        if sel and sel != "None":
            detail = df_f[df_f[id_col].astype(str) == sel].iloc[0].to_dict()
            st.json(detail)

    # -------------------------
    # Export PDF
    # -------------------------
    if st.button("Export report (PDF)"):
        txt = [f"Report for Cyber Incidents", "Generated KPIs and observations:", " - add more details here"]
        out = create_simple_pdf("Cyber Incidents report", txt, "reports/Cyber_Incidents_report.pdf")
        with open(out, "rb") as f:
            st.download_button("Download PDF", f, file_name="Cyber_Incidents_report.pdf")

# AI Chatbot for this dashboard
# Call chatbot without the undefined 'page' variable; pass a page name or context if required by your chatbot implementation
dashboard_chat()

ai_sidebar("Cyber Incidents")  # shows collapsible AI for this page
