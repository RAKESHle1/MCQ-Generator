# mcq.py
import streamlit as st
import google.generativeai as genai
import json, re, os, bcrypt, datetime, io, textwrap
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# -------------------- PAGE CONFIG --------------------
st.set_page_config(page_title="MCQ Generator", page_icon="📝", layout="wide")

# -------------------- ENV & CLIENTS --------------------
load_dotenv()
MONGO_URI = os.getenv("MONGODB_URI")
GEMINI_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("api_key") or os.getenv("GOOGLE_API_KEY")

if not MONGO_URI:
    st.error("❌ MONGODB_URI not found in environment. Please set it in your .env file.")
    st.stop()
if not GEMINI_KEY:
    st.error("❌ Gemini API key not found. Set GEMINI_API_KEY (or api_key) in your .env.")
    st.stop()

client = MongoClient(MONGO_URI)
db = client["mcq_app"]
users_collection = db["users"]
quizzes_collection = db["quizzes"]
attempts_collection = db["attempts"]

genai.configure(api_key=GEMINI_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# -------------------- AUTH HELPERS --------------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except Exception:
        if isinstance(hashed, str):
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        return False

def user_by_email(email: str):
    if not email:
        return None
    return users_collection.find_one({"email": email.strip().lower()})

def signup_user(name, email, username, password, role):
    if not (name and email and username and password and role):
        return False, "All fields are required."
    if role not in ["teacher", "student"]:
        return False, "Invalid role."
    if user_by_email(email):
        return False, "User already exists with this email!"
    users_collection.insert_one({
        "name": name.strip(),
        "email": email.strip().lower(),
        "username": username.strip(),
        "password": hash_password(password),
        "role": role,
        "created_at": datetime.datetime.utcnow()
    })
    return True, "Signup successful! Please login."

def login_user(email, password):
    user = user_by_email(email)
    if user and check_password(password or "", user["password"]):
        return True, user
    return False, None

# -------------------- PDF: QUIZ REPORT --------------------
def draw_wrapped(c, text, x, y, width_chars=95, leading=14, font=("Helvetica", 11)):
    if not text:
        return y
    c.setFont(*font)
    for line in textwrap.wrap(str(text), width=width_chars):
        c.drawString(x, y, line)
        y -= leading
    return y

def generate_quiz_pdf(results, score, total, percentage, username="User", quiz_title="MCQ Quiz"):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, f"{quiz_title} - {username}")
    y -= 22
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Score: {score}/{total} ({percentage}%)")
    y -= 18
    c.drawString(50, y, f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    y -= 28
    for i, result in enumerate(results, 1):
        if y < 120:
            c.showPage()
            y = height - 50
        c.setFont("Helvetica-Bold", 12)
        y = draw_wrapped(c, f"Q{i}: {result.get('question','')}", 50, y, width_chars=95, leading=14, font=("Helvetica-Bold", 12))
        y -= 6
        opts = result.get("options")
        if opts and isinstance(opts, dict):
            c.setFont("Helvetica", 11)
            for key in ["a", "b", "c", "d"]:
                if key in opts:
                    y = draw_wrapped(c, f"{key.upper()}) {opts[key]}", 70, y, width_chars=92, leading=13, font=("Helvetica", 11))
            y -= 4
        ua = (result.get('user_answer') or "").upper()
        ca = (result.get('correct_answer') or "").upper()
        status = "✔️ Correct" if result.get("is_correct") else "❌ Incorrect"
        y = draw_wrapped(c, f"Your Answer: {ua}", 70, y, width_chars=95, leading=13)
        y = draw_wrapped(c, f"Correct Answer: {ca}", 70, y, width_chars=95, leading=13)
        y = draw_wrapped(c, f"Result: {status}", 70, y, width_chars=95, leading=13)
        expl = result.get("explanation", "")
        if expl:
            y = draw_wrapped(c, f"Explanation: {expl}", 70, y, width_chars=92, leading=13, font=("Helvetica-Oblique", 10))
            y -= 6
        y -= 8
    c.save()
    buffer.seek(0)
    return buffer

# -------------------- MCQ GENERATION --------------------
def clean_json_response(response_text):
    response_text = re.sub(r'```(?:json)?', '', response_text, flags=re.IGNORECASE)
    response_text = response_text.replace("```", "")
    response_text = re.sub(r'json\n?', '', response_text, flags=re.IGNORECASE)
    response_text = response_text.strip()
    json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if json_match:
        return json_match.group(0)
    return response_text

def generate_mcqs(paragraph, num_questions=5, difficulty="medium"):
    prompt = f"""
Generate {num_questions} multiple-choice questions (MCQs) from this paragraph.
Difficulty: {difficulty}.
Return STRICT JSON only with this schema (no extra text):

{{
  "mcqs": [
    {{"question": "text",
      "options": {{"a": "opt1","b": "opt2","c": "opt3","d": "opt4"}},
      "answer": "a|b|c|d",
      "explanation": "why correct"}}
  ]
}}

Paragraph:
{paragraph}
"""
    try:
        response = model.generate_content(prompt)
        if not getattr(response, "text", None):
            st.error("No response from Gemini API")
            return None
        cleaned = clean_json_response(response.text)
        data = json.loads(cleaned)
        data["mcqs"] = data.get("mcqs", [])[:num_questions]
        return data
    except Exception as e:
        st.error(f"Error generating MCQs: {str(e)}")
        return None

# -------------------- QUIZ & ATTEMPT STORAGE --------------------
def save_quiz(creator_id, creator_email, title, paragraph, num_questions, difficulty, mcqs_json,
              is_teacher_quiz=False, shared=True, owner_role="teacher"):
    _cid = creator_id if isinstance(creator_id, ObjectId) else ObjectId(str(creator_id))
    doc = {
        "creator_id": _cid,
        "creator_email": creator_email,
        "title": title or (paragraph[:60] + ("..." if len(paragraph) > 60 else "")),
        "paragraph": paragraph,
        "settings": {"num_questions": num_questions, "difficulty": difficulty},
        "mcqs": mcqs_json.get("mcqs", []),
        "is_teacher_quiz": bool(is_teacher_quiz),
        "shared": bool(shared) if is_teacher_quiz else False,
        "owner_role": owner_role,
        "created_at": datetime.datetime.utcnow(),
    }
    res = quizzes_collection.insert_one(doc)
    return str(res.inserted_id)

def list_teacher_quizzes_shared(limit=100):
    return list(quizzes_collection.find({"is_teacher_quiz": True, "shared": True}).sort("created_at", -1).limit(limit))

def list_quizzes_by_creator(creator_id, limit=100):
    _cid = creator_id if isinstance(creator_id, ObjectId) else ObjectId(str(creator_id))
    return list(quizzes_collection.find({"creator_id": _cid}).sort("created_at", -1).limit(limit))

def delete_quiz(quiz_id, creator_id):
    _cid = creator_id if isinstance(creator_id, ObjectId) else ObjectId(str(creator_id))
    quizzes_collection.delete_one({"_id": ObjectId(quiz_id), "creator_id": _cid})

def save_attempt(quiz_id, student_id, student_email, results, score, total, percentage, is_self_practice=False):
    _qid = quiz_id if isinstance(quiz_id, ObjectId) else ObjectId(str(quiz_id))
    _sid = student_id if isinstance(student_id, ObjectId) else ObjectId(str(student_id))
    doc = {
        "quiz_id": _qid,
        "student_id": _sid,
        "student_email": student_email,
        "results": results,
        "score": score,
        "total": total,
        "percentage": percentage,
        "is_self_practice": bool(is_self_practice),
        "created_at": datetime.datetime.utcnow(),
    }
    res = attempts_collection.insert_one(doc)
    return str(res.inserted_id)

def list_attempts_for_quiz(quiz_id, limit=200):
    _qid = quiz_id if isinstance(quiz_id, ObjectId) else ObjectId(str(quiz_id))
    return list(attempts_collection.find({"quiz_id": _qid}).sort("created_at", -1).limit(limit))

def list_attempts_for_student(student_id, limit=200):
    _sid = student_id if isinstance(student_id, ObjectId) else ObjectId(str(student_id))
    return list(attempts_collection.find({"student_id": _sid}).sort("created_at", -1).limit(limit))
# -------------------- MCQ DISPLAY & EVALUATION --------------------
def display_mcqs_quiz(mcqs_data, quiz_context=None):
    """
    quiz_context: {
        "mode": "attempt" | "preview",
        "quiz_id": str or ObjectId or None,
        "is_teacher_quiz": bool,
        "save_attempt": bool,
        "quiz_title": str or None
    }
    """
    quiz_context = quiz_context or {}
    quiz_title = quiz_context.get("quiz_title") or "MCQ Quiz"

    if not mcqs_data or "mcqs" not in mcqs_data:
        st.error("Invalid MCQ data format")
        return

    st.subheader("🧪 Quiz Time!")
    if 'user_answers' not in st.session_state:
        st.session_state.user_answers = {}

    all_answered = True
    for i, mcq in enumerate(mcqs_data["mcqs"], 1):
        st.markdown(f"**Q{i}: {mcq['question']}**")
        options_keys = ["a", "b", "c", "d"]
        labeled_options = [f"{k.upper()}) {mcq['options'].get(k,'')}" for k in options_keys]
        option_mapping = {f"{k.upper()}) {mcq['options'].get(k,'')}": k for k in options_keys}
        selected_label = st.radio(
            f"Answer for Q{i}:",
            options=["Select an option"] + labeled_options,
            key=f"q{i}"
        )
        if selected_label != "Select an option":
            st.session_state.user_answers[f"q{i}"] = option_mapping[selected_label]
        else:
            st.session_state.user_answers[f"q{i}"] = None
            all_answered = False

    if st.button("✅ Submit Answers"):
        if all_answered:
            evaluate_quiz(mcqs_data, quiz_context)
        else:
            st.warning("⚠️ Answer all questions first!")

def evaluate_quiz(mcqs_data, quiz_context=None):
    quiz_context = quiz_context or {}
    quiz_id = quiz_context.get("quiz_id")
    save_attempt_flag = bool(quiz_context.get("save_attempt"))
    quiz_title = quiz_context.get("quiz_title") or "MCQ Quiz"
    is_self_practice = not bool(quiz_context.get("is_teacher_quiz"))

    score = 0
    total = len(mcqs_data["mcqs"])
    results = []

    for i, mcq in enumerate(mcqs_data["mcqs"], 1):
        user_answer = st.session_state.user_answers.get(f"q{i}", "")
        correct_answer = mcq['answer']
        is_correct = user_answer == correct_answer
        if is_correct:
            score += 1
        results.append({
            "question": mcq['question'],
            "options": mcq.get("options", {}),
            "user_answer": user_answer,
            "correct_answer": correct_answer,
            "is_correct": is_correct,
            "explanation": mcq.get("explanation", "")
        })

    percentage = round((score / total) * 100, 2)

    st.markdown("---")
    st.markdown(f"### 🏁 Quiz Result: {score} / {total} Correct ({percentage}%)")
    st.progress(percentage / 100)

    with st.expander("🔍 Show Correct Answers & Explanations"):
        for i, result in enumerate(results, 1):
            st.markdown(f"**Q{i}: {result['question']}**")
            opts = result.get("options", {})
            if opts:
                st.write(
                    f"A) {opts.get('a','')}\n\n"
                    f"B) {opts.get('b','')}\n\n"
                    f"C) {opts.get('c','')}\n\n"
                    f"D) {opts.get('d','')}"
                )
            st.write(f"✅ Correct Answer: **{(result['correct_answer'] or '').upper()}**")
            st.write(f"🧠 Your Answer: **{(result['user_answer'] or '').upper()}**")
            st.markdown(f"{'✔️ Correct!' if result['is_correct'] else '❌ Incorrect.'}")
            if result['explanation']:
                st.markdown(f"💡 Explanation: {result['explanation']}")
            st.write("---")

    # 🔁 Retake Button
    if st.button("🔄 Retake Quiz"):
        st.session_state.user_answers = {}
        st.rerun()

    # Save attempt (teacher quizzes and self-practice)
    if save_attempt_flag and st.session_state.get("user"):
        try:
            attempt_id = save_attempt(
                quiz_id=quiz_id,
                student_id=st.session_state.user["_id"],
                student_email=st.session_state.user["email"],
                results=results,
                score=score,
                total=total,
                percentage=percentage,
                is_self_practice=is_self_practice
            )
            st.success(f"📝 Attempt saved (ID: {attempt_id})")
        except Exception as e:
            st.error(f"Could not save attempt: {e}")

    # 📥 Download PDF Button
    pdf_buffer = generate_quiz_pdf(
        results, score, total, percentage,
        username=st.session_state.user.get("name", "User") if st.session_state.get("user") else "User",
        quiz_title=quiz_title
    )
    st.download_button(
        label="📥 Download Quiz Report (PDF)",
        data=pdf_buffer,
        file_name="quiz_report.pdf",
        mime="application/pdf"
    )

# -------------------- LOGIN / SIGNUP --------------------
if "user" not in st.session_state:
    st.session_state.user = None

if not st.session_state.user:
    st.title("🔐 Welcome to MCQ App (Teacher & Student)")
    tab1, tab2 = st.tabs(["Login", "Signup"])

    with tab1:
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            ok, user_obj = login_user(email, password)
            if ok:
                st.session_state.user = user_obj
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials.")

    with tab2:
        name = st.text_input("Full Name")
        email_s = st.text_input("Email", key="signup_email")
        username = st.text_input("Username")
        password_s = st.text_input("Password", type="password", key="signup_pw")
        role = st.selectbox("Role", ["student", "teacher"], index=0)
        if st.button("Signup"):
            success, msg = signup_user(name, email_s, username, password_s, role)
            if success:
                st.success(msg)
            else:
                st.error(msg)

else:
    user = st.session_state.user
    st.sidebar.success(f"👋 Welcome, {user.get('name','User')}! ({user.get('role','student').title()})")
    if st.sidebar.button("🚪 Logout"):
        st.session_state.user = None
        st.rerun()

# -------------------- DASHBOARDS --------------------
if st.session_state.user:
    user = st.session_state.user

    # -------------------- TEACHER DASHBOARD --------------------
    if user.get("role") == "teacher":
        tabs = st.tabs(["🧠 Create Quiz (AI)", "🗂 Manage Quizzes", "📊 View Results"])

        # ---------- Create Quiz ----------
        with tabs[0]:
            st.title("👩‍🏫 Create Quiz (AI)")
            st.sidebar.markdown("## Settings")
            num_questions = st.sidebar.slider("Number of questions:", 1, 25, 5, key="t_num")
            difficulty = st.sidebar.selectbox("Difficulty:", ["easy", "medium", "hard"], index=1, key="t_diff")

            paragraph = st.text_area("Paste Topic / Paragraph", height=220, placeholder="Paste your content here...")
            title = st.text_input("Quiz Title (optional)")

            if st.button("🤖 Generate MCQs", type="primary"):
                if paragraph.strip():
                    with st.spinner("Generating MCQs..."):
                        result = generate_mcqs(paragraph, num_questions, difficulty)
                    if result:
                        st.session_state['mcqs_preview'] = result
                        st.session_state['preview_paragraph'] = paragraph
                        st.session_state['preview_title'] = title
                        st.success("✅ MCQs generated! Review below before publishing.")
                    else:
                        st.error("❌ Failed to generate MCQs.")
                else:
                    st.warning("⚠ Please paste a paragraph/topic.")

            if 'mcqs_preview' in st.session_state:
                st.markdown("---")
                st.subheader("Preview Generated MCQs")
                display_mcqs_quiz(st.session_state['mcqs_preview'], quiz_context={
                    "mode": "preview",
                    "save_attempt": False,
                    "quiz_title": st.session_state.get('preview_title', 'Preview Quiz')
                })

                if st.button("📢 Publish to Students"):
                    try:
                        quiz_id = save_quiz(
                            creator_id=user["_id"],
                            creator_email=user["email"],
                            title=st.session_state.get('preview_title', ''),
                            paragraph=st.session_state.get('preview_paragraph', ''),
                            num_questions=num_questions,
                            difficulty=difficulty,
                            mcqs_json=st.session_state['mcqs_preview'],
                            is_teacher_quiz=True,
                            shared=True,
                            owner_role="teacher"
                        )
                        st.success(f"✅ Quiz published! Quiz ID: {quiz_id}")
                        st.session_state.pop('mcqs_preview', None)
                        st.session_state.pop('preview_paragraph', None)
                        st.session_state.pop('preview_title', None)
                    except Exception as e:
                        st.error(f"❌ Could not publish quiz: {e}")

        # ---------- Manage Quizzes ----------
        with tabs[1]:
            st.title("🗂 Manage Your Quizzes")
            items = list_quizzes_by_creator(user["_id"], limit=100)
            if not items:
                st.info("No quizzes yet.")
            else:
                for doc in items:
                    with st.expander(f"🗒 {doc.get('title','(untitled)')} — {doc['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}"):
                        st.write(
                            f"**Questions:** {len(doc.get('mcqs', []))} | "
                            f"**Difficulty:** {doc['settings']['difficulty']} | "
                            f"**Shared:** {'Yes' if doc.get('shared') else 'No'} | "
                            f"**Teacher Quiz:** {'Yes' if doc.get('is_teacher_quiz') else 'No'}"
                        )
                        st.code(doc.get("paragraph", "")[:800] + ("..." if len(doc.get("paragraph","")) > 800 else ""))

                        attempts = list_attempts_for_quiz(doc["_id"])
                        st.write(f"🧪 Attempts: {len(attempts)}")

                        colA, colB = st.columns([1,1])
                        with colA:
                            if st.button("Delete", key=f"del_{doc['_id']}"):
                                delete_quiz(str(doc["_id"]), user["_id"])
                                st.rerun()
                        with colB:
                            if st.button("Preview", key=f"prev_{doc['_id']}"):
                                st.session_state['mcqs_data_preview'] = {"mcqs": doc.get("mcqs", [])}
                                st.session_state['preview_quiz_meta'] = {
                                    "quiz_id": str(doc["_id"]),
                                    "title": doc.get("title", "Quiz")
                                }

                if 'mcqs_data_preview' in st.session_state:
                    st.markdown("---")
                    st.subheader(f"Preview: {st.session_state.get('preview_quiz_meta',{}).get('title','Quiz')}")
                    display_mcqs_quiz(st.session_state['mcqs_data_preview'], quiz_context={
                        "mode": "preview",
                        "quiz_id": st.session_state.get('preview_quiz_meta',{}).get('quiz_id'),
                        "is_teacher_quiz": True,
                        "save_attempt": False,
                        "quiz_title": st.session_state.get('preview_quiz_meta',{}).get('title', 'Quiz')
                    })
                    if st.button("❌ Close Preview"):
                        st.session_state.pop('mcqs_data_preview', None)
                        st.session_state.pop('preview_quiz_meta', None)
                        st.rerun()

        # ---------- View Results ----------
        with tabs[2]:
            st.title("📊 Results")
            my_quizzes = list_quizzes_by_creator(user["_id"], limit=200)
            if not my_quizzes:
                st.info("No quizzes yet.")
            else:
                quiz_map = {str(q["_id"]): q for q in my_quizzes}
                selected = st.selectbox(
                    "Select quiz to view attempts",
                    options=list(quiz_map.keys()),
                    format_func=lambda qid: f"{quiz_map[qid].get('title','(untitled)')} ({qid})"
                )
                if selected:
                    cho = quiz_map[selected]
                    attempts = list_attempts_for_quiz(cho["_id"])
                    if not attempts:
                        st.info("No attempts yet for this quiz.")
                    else:
                        for att in attempts:
                            with st.expander(f"👤 {att['student_email']} — {att['score']}/{att['total']} ({att['percentage']}%) — {att['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}"):
                                st.write("Attempt detail:")
                                for i, res in enumerate(att.get("results", []), 1):
                                    st.markdown(f"**Q{i}: {res.get('question','')}**")
                                    opts = res.get("options", {})
                                    if opts:
                                        st.write(f"A) {opts.get('a','')}")
                                        st.write(f"B) {opts.get('b','')}")
                                        st.write(f"C) {opts.get('c','')}")
                                        st.write(f"D) {opts.get('d','')}")
                                    st.write(f"✅ Correct: **{(res.get('correct_answer') or '').upper()}**")
                                    st.write(f"🧠 Student: **{(res.get('user_answer') or '').upper()}**")
                                    st.write("✔️" if res.get("is_correct") else "❌")
                                    if res.get("explanation"):
                                        st.markdown(f"💡 {res['explanation']}")
                                    st.write("---")
                                pdf_buffer = generate_quiz_pdf(
                                    att.get("results", []),
                                    att.get("score", 0),
                                    att.get("total", 0),
                                    att.get("percentage", 0.0),
                                    username=att['student_email'],
                                    quiz_title=cho.get("title","Teacher Quiz")
                                )
                                st.download_button(
                                    "📥 Download this Attempt as PDF",
                                    data=pdf_buffer,
                                    file_name=f"{cho.get('title','quiz')}_{att['student_email']}.pdf",
                                    mime="application/pdf",
                                    key=f"pdf_{att['_id']}"
                                )

    # -------------------- STUDENT DASHBOARD --------------------
    else:
        tabs = st.tabs(["📘 Teacher Quizzes", "📝 Self Practice (Generate)", "📊 My Results"])

        # ---------- Teacher Quizzes ----------
        with tabs[0]:
            st.title("📘 Teacher Quizzes")
            items = list_teacher_quizzes_shared(limit=100)
            if not items:
                st.info("No teacher quizzes available yet.")
            else:
                for doc in items:
                    with st.expander(f"{doc.get('title','(untitled)')} — {doc['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}"):
                        st.write(
                            f"**Questions:** {len(doc.get('mcqs', []))} | "
                            f"**Difficulty:** {doc['settings']['difficulty']} | "
                            f"**By:** {doc.get('creator_email','')}"
                        )
                        if st.button("Attempt this Quiz", key=f"attempt_{doc['_id']}"):
                            st.session_state['mcqs_active'] = {"mcqs": doc.get("mcqs", [])}
                            st.session_state['active_quiz_meta'] = {
                                "quiz_id": str(doc["_id"]),
                                "title": doc.get("title","Teacher Quiz"),
                                "is_teacher_quiz": True
                            }
                            st.session_state['user_answers'] = {}
                            st.success("Quiz loaded below!")

            if 'mcqs_active' in st.session_state:
                st.markdown("---")
                meta = st.session_state.get('active_quiz_meta', {})
                display_mcqs_quiz(st.session_state['mcqs_active'], quiz_context={
                    "mode": "attempt",
                    "quiz_id": meta.get("quiz_id"),
                    "is_teacher_quiz": True,
                    "save_attempt": True,
                    "quiz_title": meta.get("title","Teacher Quiz")
                })
                if st.button("❌ Close Quiz"):
                    st.session_state.pop('mcqs_active', None)
                    st.session_state.pop('active_quiz_meta', None)
                    st.rerun()

        # ---------- Self Practice (AI) ----------
        with tabs[1]:
            st.title("📝 Self Practice (AI)")
            st.sidebar.markdown("## Settings")
            num_questions = st.sidebar.slider("Number of questions:", 1, 25, 5, key="s_num")
            difficulty = st.sidebar.selectbox("Difficulty:", ["easy", "medium", "hard"], index=1, key="s_diff")

            paragraph = st.text_area("Paste Topic / Paragraph", height=220, placeholder="Paste your content here...")
            title = st.text_input("Quiz Title (optional for your history)")

            if st.button("🚀 Generate Self Practice Quiz", type="primary"):
                if paragraph.strip():
                    with st.spinner("🤖 Generating MCQs..."):
                        result = generate_mcqs(paragraph, num_questions, difficulty)
                    if result:
                        # Save as a quiz owned by student, but not shared
                        quiz_id = save_quiz(
                            creator_id=user["_id"],
                            creator_email=user["email"],
                            title=title,
                            paragraph=paragraph,
                            num_questions=num_questions,
                            difficulty=difficulty,
                            mcqs_json=result,
                            is_teacher_quiz=False,
                            shared=False,
                            owner_role="student"
                        )
                        st.success(f"✅ Self practice quiz saved (ID: {quiz_id})")
                        st.info("This quiz is private to you. Attempt & download PDF.")
                        st.markdown("---")
                        st.subheader("Start Practice")
                        st.session_state['self_mcqs'] = result
                        st.session_state['self_meta'] = {"quiz_id": quiz_id, "title": title or "Self Practice"}
                        st.session_state['user_answers'] = {}
                    else:
                        st.error("❌ Failed to generate MCQs.")
                else:
                    st.warning("⚠ Please paste a paragraph/topic.")

            if 'self_mcqs' in st.session_state:
                meta = st.session_state.get('self_meta', {})
                display_mcqs_quiz(st.session_state['self_mcqs'], quiz_context={
                    "mode": "attempt",
                    "quiz_id": meta.get("quiz_id"),
                    "is_teacher_quiz": False,
                    "save_attempt": True,    # Save to attempts but marked is_self_practice=True
                    "quiz_title": meta.get("title","Self Practice")
                })
                if st.button("🗑 Clear Self Practice"):
                    st.session_state.pop('self_mcqs', None)
                    st.session_state.pop('self_meta', None)
                    st.rerun()

        # ---------- My Results ----------
        with tabs[2]:
            st.title("📊 My Results")
            my_attempts = list_attempts_for_student(user["_id"], limit=200)
            if not my_attempts:
                st.info("No attempts yet.")
            else:
                for att in my_attempts:
                    # Fetch quiz (for title)
                    q = quizzes_collection.find_one({"_id": ObjectId(att["quiz_id"])}) if att.get("quiz_id") else None
                    qtitle = q.get("title","(untitled)") if q else "(unknown quiz)"
                    tag = "Self" if att.get("is_self_practice") else "Teacher"

                    with st.expander(f"[{tag}] {qtitle} — {att['score']}/{att['total']} ({att['percentage']}%) — {att['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}"):
                        for i, res in enumerate(att.get("results", []), 1):
                            st.markdown(f"**Q{i}: {res.get('question','')}**")
                            opts = res.get("options", {})
                            if opts:
                                st.write(f"A) {opts.get('a','')}")
                                st.write(f"B) {opts.get('b','')}")
                                st.write(f"C) {opts.get('c','')}")
                                st.write(f"D) {opts.get('d','')}")
                            st.write(f"✅ Correct: **{(res.get('correct_answer') or '').upper()}**")
                            st.write(f"🧠 Your: **{(res.get('user_answer') or '').upper()}**")
                            st.write("✔️" if res.get("is_correct") else "❌")
                            if res.get("explanation"):
                                st.markdown(f"💡 {res['explanation']}")
                            st.write("---")

                        # Download PDF per attempt
                        pdf_buffer = generate_quiz_pdf(
                            att.get("results", []),
                            att.get("score", 0),
                            att.get("total", 0),
                            att.get("percentage", 0.0),
                            username=user.get("name","User"),
                            quiz_title=qtitle
                        )
                        st.download_button(
                            "📥 Download Attempt PDF",
                            data=pdf_buffer,
                            file_name=f"{qtitle.replace(' ','_')}_attempt.pdf",
                            mime="application/pdf",
                            key=f"my_pdf_{att['_id']}"
                        )
