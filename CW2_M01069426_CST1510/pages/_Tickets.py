import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import timedelta
from utils import load_csv, create_simple_pdf
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

    /* Glass panel */
    .glass-panel {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 20px;
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        padding: 30px;
        margin: 20px auto;
        border: 2px solid rgba(255, 105, 180, 0.5);
        text-align: center;
        max-width: 90%;
        overflow: hidden;
        height: 150px;
        position: relative;
    }

    /* Animated code lines */
    .code-line {
        font-family: 'Courier New', monospace;
        color: #ff69b4;
        white-space: pre;
        position: absolute;
        width: 100%;
        animation: scroll 5s linear infinite;
    }

    @keyframes scroll {
        0% {top: 100%;}
        100% {top: -100%;}
    }

    /* Streamlit metric styling for neon */
    .stMetric label {color: #ff69b4;}
    .stMetric div[data-testid="stMetricValue"] {color: #ff69b4;}
    </style>
""", unsafe_allow_html=True)

# ============================
# TITLE
# ============================
st.markdown('<div class="dashboard-title">IT TICKETS - DASHBOARD</div>', unsafe_allow_html=True)

# ============================
# DRAGGABLE INTERACTIVE NEON CONSTELLATION PANEL WITH TOGGLE
# ============================
import streamlit as st
import streamlit.components.v1 as components

# Toggle button
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
            x0:0, y0:0, // placeholder for offset
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

        // draw stars
        stars.forEach(star=>{
            star.twinkle = (star.twinkle+0.02)%1.0;
            const opacity = 0.5 + 0.5*Math.sin(star.twinkle*Math.PI*2);
            const dx = mouse.x - star.x;
            const dy = mouse.y - star.y;
            star.x += dx*star.parallax*0.02;
            star.y += dy*star.parallax*0.02;

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
# LOAD DATA
# ============================
tickets_df = load_csv("data/it_tickets.csv")

if tickets_df.empty:
    st.info("No ticket data found.")
else:
    # ----------------------------
    # COLUMN NORMALIZATION
    # ----------------------------
    cols = {c.lower(): c for c in tickets_df.columns}
    def col(c): return cols.get(c.lower())

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
    df_f = tickets_df.copy()

    if status_col:
        statuses = ["All"] + sorted(df_f[status_col].dropna().unique().astype(str))
        status_choice = st.sidebar.selectbox("Status", statuses)
        if status_choice != "All":
            df_f = df_f[df_f[status_col] == status_choice]

    if priority_col:
        priorities = ["All"] + sorted(df_f[priority_col].dropna().unique().astype(str))
        priority_choice = st.sidebar.selectbox("Priority", priorities)
        if priority_choice != "All":
            df_f = df_f[df_f[priority_col] == priority_choice]

    if assigned_col:
        assigned_opts = ["All"] + sorted(df_f[assigned_col].dropna().unique().astype(str))
        assigned_choice = st.sidebar.selectbox("Assigned To", assigned_opts)
        if assigned_choice != "All":
            df_f = df_f[df_f[assigned_col] == assigned_choice]

    if created_col:
        df_f["_created_dt"] = pd.to_datetime(df_f[created_col], errors="coerce")
        min_date, max_date = df_f["_created_dt"].min(), df_f["_created_dt"].max()
        if pd.notna(min_date) and pd.notna(max_date):
            date_range = st.sidebar.date_input("Created Date Range", (min_date.date(), max_date.date()))
            if len(date_range) == 2:
                start, end = date_range
                df_f = df_f[(df_f["_created_dt"] >= pd.to_datetime(start)) &
                            (df_f["_created_dt"] <= pd.to_datetime(end))]

    if desc_col:
        keyword = st.sidebar.text_input("Search description")
        if keyword.strip():
            df_f = df_f[df_f[desc_col].astype(str).str.contains(keyword, case=False, na=False)]

    if st.sidebar.button("Reset Filters"):
        st.experimental_rerun()

    # ----------------------------
    # KPIs
    # ----------------------------
    total_tickets = len(df_f)
    status_series = df_f[status_col].astype(str).str.lower() if status_col else pd.Series([])
    open_count = status_series.isin(["open", "in progress", "pending"]).sum()
    closed_count = status_series.isin(["closed", "resolved"]).sum()
    avg_resolution = df_f[resolution_col].astype(float).mean() if resolution_col else None

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total Tickets", total_tickets)
    k2.metric("Open", open_count)
    k3.metric("Closed", closed_count)
    k4.metric("Avg Resolution (hrs)", f"{avg_resolution:.2f}" if avg_resolution else "N/A")

    st.markdown("---")

    # ----------------------------
    # CHARTS
    # ----------------------------
    left, right = st.columns(2)

    with left:
        if status_col:
            st.subheader("Tickets by Status")
            status_counts = df_f[status_col].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig_status = px.bar(status_counts, x="status", y="count", text="count",
                                color="status", color_discrete_map={"Open": "red", "Closed": "green"})
            st.plotly_chart(fig_status, use_container_width=True)

        if priority_col and status_col and assigned_col:
            st.subheader("Priority → Status → Assigned")
            sun = df_f.groupby([priority_col, status_col, assigned_col]).size().reset_index(name="count")
            fig_sun = px.sunburst(sun, path=[priority_col, status_col, assigned_col], values="count",
                                  color_discrete_sequence=px.colors.sequential.Plasma)
            st.plotly_chart(fig_sun, use_container_width=True)

    with right:
        if priority_col:
            st.subheader("Priority Distribution")
            pri_counts = df_f[priority_col].value_counts().reset_index()
            pri_counts.columns = ["priority", "count"]
            fig_pri = px.pie(pri_counts, names="priority", values="count",
                             color_discrete_sequence=px.colors.sequential.Plasma)
            st.plotly_chart(fig_pri, use_container_width=True)

        if resolution_col:
            st.subheader("Resolution Time Distribution")
            res = pd.to_numeric(df_f[resolution_col], errors="coerce").dropna()
            fig_res = px.histogram(res, nbins=20, color_discrete_sequence=["#ff69b4"])
            st.plotly_chart(fig_res, use_container_width=True)

    st.markdown("---")

    # ----------------------------
    # GANTT TIMELINE
    # ----------------------------
    st.subheader("Ticket Timeline (Gantt View)")
    if created_col:
        gantt_df = df_f.copy()
        gantt_df["_start"] = pd.to_datetime(gantt_df[created_col], errors="coerce")
        if resolution_col:
            gantt_df["_dur"] = pd.to_numeric(gantt_df[resolution_col], errors="coerce").fillna(0)
            gantt_df["_finish"] = gantt_df["_start"] + gantt_df["_dur"].apply(lambda x: timedelta(hours=float(x)))
        else:
            gantt_df["_finish"] = gantt_df["_start"]
        gantt_df["_task"] = gantt_df.index.astype(str)
        gantt_df = gantt_df.dropna(subset=["_start"])
        if not gantt_df.empty:
            fig_gantt = px.timeline(gantt_df, x_start="_start", x_end="_finish", y="_task",
                                    color=priority_col if priority_col else status_col,
                                    color_discrete_sequence=px.colors.sequential.Plasma)
            fig_gantt.update_yaxes(autorange="reversed")
            st.plotly_chart(fig_gantt, use_container_width=True)
        else:
            st.info("Not enough date information for Gantt chart.")

    # ----------------------------
    # TABLE
    # ----------------------------
    st.markdown("---")
    with st.expander("Show Tickets Table"):
        st.dataframe(df_f)

# ----------------------------
# EXPORT PDF
# ----------------------------
if st.button("Export report (PDF)"):
    txt = [f"Report for IT Tickets", "Generated KPIs and observations:", " - add more details here"]
    out = create_simple_pdf("IT Tickets report", txt, "reports/IT_Tickets_report.pdf")
    with open(out, "rb") as f:
        st.download_button("Download PDF", f, file_name="IT_Tickets_report.pdf")

# AI Chatbot for this dashboard
# Call chatbot without the undefined 'page' variable; pass a page name or context if required by your chatbot implementation
dashboard_chat("IT Tickets")

# provide an explicit page context to avoid NameError; adjust the string to suit your chatbot's expected context
page = "IT Tickets"
ai_sidebar(page)  # shows collapsible AI for this page
