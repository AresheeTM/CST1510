
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
st.markdown('<div class="dashboard-title">DATASETS — DASHBOARD</div>', unsafe_allow_html=True)

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
        dragStart.y = e.clientY - dragStart.y;
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
# EXISTING DATASETS DASHBOARD CODE
# ============================
st.title("Datasets — Dashboard")

# Load CSV
datasets_df = load_csv("data/datasets_metadata.csv")

if datasets_df.empty:
    st.info("No dataset metadata found.")
else:
    # Normalize column lookup
    cols = {c.lower(): c for c in datasets_df.columns}
    def col(c): return cols.get(c.lower())

    name_col = col("name")
    rows_col = col("rows")
    cols_col = col("columns")
    uploader_col = col("uploaded_by")
    upload_date_col = col("upload_date")
    dataset_id_col = col("dataset_id") or col("id")

    # -------------------------
    # Sidebar Filters
    # -------------------------
    st.sidebar.header("Filter datasets")
    df_f = datasets_df.copy()

    if uploader_col:
        uploaders = ["All"] + sorted(df_f[uploader_col].dropna().unique().astype(str))
        up_choice = st.sidebar.selectbox("Uploaded by", uploaders)
        if up_choice != "All":
            df_f = df_f[df_f[uploader_col] == up_choice]

    if upload_date_col:
        df_f["_udt"] = pd.to_datetime(df_f[upload_date_col], errors="coerce")
        min_d, max_d = df_f["_udt"].min(), df_f["_udt"].max()
        if pd.notna(min_d) and pd.notna(max_d):
            rng = st.sidebar.date_input("Upload date range", (min_d.date(), max_d.date()))
            if len(rng) == 2:
                start, end = rng
                df_f = df_f[(df_f["_udt"] >= pd.to_datetime(start)) & (df_f["_udt"] <= pd.to_datetime(end))]

    if name_col:
        kw = st.sidebar.text_input("Search dataset name")
        if kw.strip():
            df_f = df_f[df_f[name_col].astype(str).str.contains(kw, case=False, na=False)]

    if st.sidebar.button("Reset dataset filters"):
        st.experimental_rerun()

    # -------------------------
    # KPIs, charts, tables etc.
    # (all your existing code below stays exactly the same)

    # -------------------------
    # KPIs
    # -------------------------
    total_datasets = len(df_f)
    total_rows = df_f[rows_col].dropna().astype(float).sum() if rows_col else None
    avg_rows = df_f[rows_col].dropna().astype(float).mean() if rows_col else None
    max_rows = df_f[rows_col].dropna().astype(float).max() if rows_col else None
    min_rows = df_f[rows_col].dropna().astype(float).min() if rows_col else None

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total datasets", total_datasets)
    k2.metric("Total rows (sum)", f"{int(total_rows):,}" if total_rows else "N/A")
    k3.metric("Avg rows per dataset", f"{avg_rows:.2f}" if avg_rows else "N/A")
    k4.metric("Rows range", f"{int(min_rows):,} - {int(max_rows):,}" if rows_col else "N/A")
    st.markdown("---")

    # -------------------------
    # Charts
    # -------------------------
    left, right = st.columns(2)

    with left:
        if uploader_col:
            st.subheader("Uploads by User")
            uploader_counts = df_f[uploader_col].fillna("Unknown").value_counts().reset_index()
            uploader_counts.columns = ["uploader", "count"]
            fig_up = px.bar(uploader_counts, x="uploader", y="count", text="count")
            st.plotly_chart(fig_up, use_container_width=True)

        if name_col and rows_col:
            st.subheader("Top Datasets by Row Count")
            topn = st.slider("Top N", 3, 20, 10)
            top_df = df_f[[name_col, rows_col]].dropna().sort_values(by=rows_col, ascending=False).head(topn)
            fig_top = px.bar(top_df, x=name_col, y=rows_col, text=rows_col)
            st.plotly_chart(fig_top, use_container_width=True)

        # Pie chart of uploader contributions
        if uploader_col:
            st.subheader("Uploader Contribution (%)")
            fig_pie = px.pie(uploader_counts, names="uploader", values="count")
            st.plotly_chart(fig_pie, use_container_width=True)

    with right:
        if rows_col:
            st.subheader("Rows Distribution")
            rows_series = pd.to_numeric(df_f[rows_col], errors="coerce").dropna()
            fig_rows = px.histogram(rows_series, nbins=30)
            st.plotly_chart(fig_rows, use_container_width=True)

            st.subheader("Rows Boxplot")
            fig_box = px.box(df_f, y=rows_col, points="outliers")
            st.plotly_chart(fig_box, use_container_width=True)

        if cols_col:
            st.subheader("Columns Distribution")
            cols_series = pd.to_numeric(df_f[cols_col], errors="coerce").dropna()
            fig_cols = px.histogram(cols_series, nbins=20)
            st.plotly_chart(fig_cols, use_container_width=True)

    st.markdown("---")

    # -------------------------
    # Advanced Charts
    # -------------------------
    # Treemap
    if rows_col and name_col:
        st.subheader("Dataset Size Treemap")
        fig_tree = px.treemap(df_f, path=[name_col], values=rows_col)
        st.plotly_chart(fig_tree, use_container_width=True)

    # Rows vs Columns
    if rows_col and cols_col:
        st.subheader("Rows vs Columns Scatter")
        fig_sc = px.scatter(df_f, x=cols_col, y=rows_col, hover_data=[name_col])
        st.plotly_chart(fig_sc, use_container_width=True)

    # Upload trends
    if upload_date_col:
        st.subheader("Upload Trend Over Time")
        df_t = df_f.copy()
        df_t["_udt"] = pd.to_datetime(df_t[upload_date_col], errors="coerce")
        df_t = df_t.dropna(subset=["_udt"])
        df_t["_date"] = df_t["_udt"].dt.date
        trend = df_t.groupby("_date").size().reset_index(name="count")
        fig_trend = px.line(trend, x="_date", y="count", markers=True)
        st.plotly_chart(fig_trend, use_container_width=True)

        # Uploads by Hour
        st.subheader("Uploads by Hour")
        df_t["_hour"] = df_t["_udt"].dt.hour
        hourly = df_t.groupby("_hour").size().reset_index(name="count")
        fig_hour = px.bar(hourly, x="_hour", y="count", text="count")
        st.plotly_chart(fig_hour, use_container_width=True)

    # Numeric correlation heatmap
    numeric_df = df_f.select_dtypes(include=["int64", "float64"])
    if not numeric_df.empty:
        st.subheader("Correlation Heatmap")
        corr = numeric_df.corr()
        fig_heat = px.imshow(corr, text_auto=True, aspect="auto")
        st.plotly_chart(fig_heat, use_container_width=True)

    # -------------------------
    # Table
    # -------------------------
    st.markdown("---")
    with st.expander("Show datasets table"):
        st.dataframe(df_f)

# -------------------------
# Export PDF
# -------------------------
if st.button("Export report (PDF)"):
    txt = [f"Report for Datasets", "Generated KPIs and observations:", " - add more details here"]
    out = create_simple_pdf("Datasets report", txt, "reports/Datasets_report.pdf")
    with open(out, "rb") as f:
        st.download_button("Download PDF", f, file_name="Datasets_report.pdf")

# AI Chatbot for this dashboard
# Call chatbot without the undefined 'page' variable; pass a page name or context if required by your chatbot implementation
dashboard_chat("Datasets")

# pass a literal page identifier for the sidebar helper
ai_sidebar("datasets")  # shows collapsible AI for this page
