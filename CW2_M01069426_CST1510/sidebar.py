# sidebar.py
# ============================
# Upgraded user sidebar with AI assistant
# ============================

import streamlit as st
import streamlit.components.v1 as components
from ai_chatbot import dashboard_chat

def user_sidebar():
    # ---------------------------
    # Session init
    # ---------------------------
    if "user" not in st.session_state:
        st.session_state["user"] = None
    if "show_user_menu" not in st.session_state:
        st.session_state["show_user_menu"] = False
    if "show_ai_menu" not in st.session_state:
        st.session_state["show_ai_menu"] = False
    if "js_event" not in st.session_state:
        st.session_state["js_event"] = None
    if "current_page" not in st.session_state:
        st.session_state["current_page"] = "Home"

    # ---------------------------
    # Initialize chat histories for AI assistant
    # ---------------------------
    page_keys = ["Home", "Cyber Incidents", "Datasets", "Tickets", "IT Tickets"]
    for page in page_keys:
        chat_key = f"chat_history_{page.lower().replace(' ','_')}"
        if chat_key not in st.session_state:
            st.session_state[chat_key] = []



    # ---------------------------
    # CSS
    # ---------------------------
    st.markdown("""
    <style>
    [data-testid="stSidebar"] {background-color:#0a0a0a;color:#ff69b4;font-family:'Courier New', monospace;}
    .profile-pic {width:70px;height:70px;border-radius:50%;object-fit:cover;border:2px solid #ff69b4;box-shadow:0 0 10px #ff69b4;cursor:pointer;}
    .user-label {color:#ff69b4;font-weight:bold;font-size:1em;display:block;margin-top:5px;}

    /* Neon AI Icon */
    @keyframes pulseAI {0% {transform: scale(1);filter: drop-shadow(0 0 5px #ff69b4);} 50% {transform: scale(1.3);filter: drop-shadow(0 0 20px #ff69b4) drop-shadow(0 0 30px #ff1493);} 100% {transform: scale(1);filter: drop-shadow(0 0 5px #ff69b4);}}
    .ai-icon {animation: pulseAI 1.5s infinite; font-size:1.8em; cursor:pointer; margin-top:10px;}
    .ai-icon:hover {filter: drop-shadow(0 0 25px #ff69b4) drop-shadow(0 0 50px #ff1493);}

    /* AI Typing dots animation */
    .typing-dots::after {
        content: '.';
        animation: blink 1s infinite steps(1);
    }
    @keyframes blink {
        0%, 20% { content: ''; }
        40%, 60% { content: '.'; }
        80% { content: '..'; }
        100% { content: '...'; }
    }

    /* User & AI hidden panels */
    .user-menu, .ai-menu {display:none;margin-top:10px;padding:8px;border-radius:10px;background-color:#1b0f2e;border:1px solid #ff69b430;}
    .user-menu.show, .ai-menu.show {display:block;}

    .stButton button {background-color:#ff69b4;color:#0a0a0a;border-radius:8px;padding:6px 12px;font-weight:bold;border:none;width:100%;margin-top:5px;transition:0.3s;}
    .stButton button:hover {background-color:#ff1493;}
    </style>
    """, unsafe_allow_html=True)


    # ---------------------------
    # Profile
    # ---------------------------
    profile_pic = "images/avatars/default.png"
    if st.session_state["user"]:

        profile_pic_from_db = st.session_state.get("avatar_file", None)
        if profile_pic_from_db:
            profile_pic = f"images/avatars/{profile_pic_from_db}"

    profile_html = f"""
        <div style="text-align:center;">
            <img src="/{profile_pic}" class="profile-pic" id="profile-icon" />
            <span class="user-label">{st.session_state.user or "Guest"}</span>
        </div>
        <div id="user-menu" class="user-menu">
            <button id="logout-btn">Logout</button>
            <button id="signin-btn">Sign in as another user</button>
        </div>
        """
    st.sidebar.markdown(profile_html, unsafe_allow_html=True)

    # ============================
    # AI Assistant (Neon Icon + Sidebar Chat)
    # ============================
    ai_html = """
    <div style="text-align:center;">
        <!-- Replace emoji with neon SVG icon -->
        <svg id="ai-icon" class="ai-icon" width="50" height="50" viewBox="0 0 64 64">
            <circle cx="32" cy="32" r="30" stroke="#ff69b4" stroke-width="4" fill="none" />
            <text x="32" y="38" text-anchor="middle" font-size="28" fill="#ff69b4" font-family="Courier New, monospace">AI</text>
        </svg>
    </div>

    <div id="ai-menu" class="ai-menu">
        <div id="ai-chat-area">
            <!-- Streamlit chat will appear here -->
        </div>
    </div>

    <script>
    const audio = new Audio("/sounds/typing.mp3");  // Add typing sound file in /sounds folder

    // Toggle AI panel
    document.getElementById('ai-icon').addEventListener('click', () => {
        const menu = document.getElementById('ai-menu');
        menu.classList.toggle('show');
        if (menu.classList.contains('show')) {
            audio.play();  // Play typing sound when opened
        }
    });

    // Neon blinking dots typing animation
    const style = document.createElement('style');
    style.innerHTML = `
    .typing-dots::after {
        content: '.';
        animation: blink 1s infinite steps(1);
    }
    @keyframes blink {
        0%, 20% { content: ''; }
        40%, 60% { content: '.'; }
        80% { content: '..'; }
        100% { content: '...'; }
    }`;
    document.head.appendChild(style);
    </script>
    """

    st.sidebar.markdown(ai_html, unsafe_allow_html=True)

    # ============================
    # Inject Streamlit AI chat into sidebar
    # ============================
    if st.session_state.get("show_ai_menu", True):
        current_page = st.session_state.get("current_page", "Home")
        with st.sidebar:
            dashboard_chat(current_page)  # Now with neon typing + optional sound

        # ---------------------------
        # AI Icon + Typing
        # ---------------------------
        ai_html = """
        <div style="text-align:center;">
            <span class="ai-icon" id="ai-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ff69b4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="12" cy="12" r="10"></circle>
                  <path d="M8 12h8"></path>
                  <path d="M12 8v8"></path>
                </svg>
            </span>
        </div>
        <div id="ai-menu" class="ai-menu">
            <div id="ai-chat-area">
                <!-- Streamlit AI chat appears here -->
            </div>
        </div>
        <audio id="ai-typing-sound" src="https://freesound.org/data/previews/341/341695_5260872-lq.mp3" preload="auto"></audio>

        <script>
        // Toggle menus
        document.getElementById('profile-icon').addEventListener('click',()=>{document.getElementById('user-menu').classList.toggle('show');});
        document.getElementById('ai-icon').addEventListener('click',()=>{document.getElementById('ai-menu').classList.toggle('show');});

        document.getElementById('logout-btn').addEventListener('click',()=>{window.parent.postMessage({isStreamlitMessage:true,type:"streamlit:setEvent",event:"logout"},"*");});
        document.getElementById('signin-btn').addEventListener('click',()=>{window.parent.postMessage({isStreamlitMessage:true,type:"streamlit:setEvent",event:"signin"},"*");});

        // Listen for typing events from Streamlit
        window.addEventListener("message",(event)=>{
            if(event.data?.type==="streamlit:setComponentValue"){
                const val = event.data.value;
                if(val==="ai_typing_on"){
                    const sound = document.getElementById("ai-typing-sound");
                    sound.play();
                    let area = document.getElementById("ai-chat-area");
                    area.innerHTML = "AI typing<span class='typing-dots'></span><span class='typing-dots'></span><span class='typing-dots'></span>";
                }
                if(val==="ai_typing_off"){
                    let area = document.getElementById("ai-chat-area");
                    area.innerHTML = "";
                }
            }
        });
        </script>
        """
        st.sidebar.markdown(ai_html, unsafe_allow_html=True)

        # ---------------------------
        # AI Chat Panel in Streamlit
        # ---------------------------
        if st.session_state.get("show_ai_menu", True):
            with st.sidebar:
                dashboard_chat(st.session_state.get("current_page","Home"))

        # ---------------------------
        # JS → Python event handling
        # ---------------------------
        components.html("""
        <script>
        window.addEventListener("message",(event)=>{
            if(event.data?.type==="streamlit:setEvent"){
                window.parent.postMessage({isStreamlitMessage:true,type:"streamlit:setComponentValue",value:event.data.event},"*");
            }
        });
        </script>
        """, height=0)

        # ---------------------------
        # Logout / Signin
        # ---------------------------
        if st.session_state.js_event=="logout" or st.session_state.js_event=="signin":
            st.session_state.user = None
            st.session_state.show_user_menu = False
            st.session_state.show_ai_menu = False
            st.experimental_rerun()





