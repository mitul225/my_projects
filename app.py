#import streamlit as st
#import psycopg2
#import pandas as pd
#from db_connection import get_connection  # your connection file

#st.set_page_config(page_title="SEO Blog Manager", layout="wide")

#pip install pyotp qrcode[pil] streamlit-authenticator
import streamlit as st
import psycopg2
import pandas as pd
import pyotp   # 🔑 for Google Authenticator
import qrcode
import io
import bcrypt
from db_connection import get_connection  # your connection file

st.set_page_config(page_title="SEO Blog Manager", layout="wide")

# ------------------- Session State ------------------- #
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "awaiting_otp" not in st.session_state:
    st.session_state["awaiting_otp"] = False
if "auth_user" not in st.session_state:
    st.session_state["auth_user"] = None
    
# ------------------- DB UTILS ------------------- #

#def run_query(query, params=None, fetch=False, many=False):
    
    # Open a new connection for each query safely.
    
#    conn = get_connection()
#    try:
#        with conn:
#            with conn.cursor() as cur:
#                if many:
#                    cur.executemany(query, params)
#                else:
#                    cur.execute(query, params)
#                if fetch:
#                    rows = cur.fetchall()
#                    return rows
#    finally:
#        conn.close()


def run_query(query, params=None, fetch=False, many=False):
    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                if params is not None and not isinstance(params, (list, tuple)):
                    params = (params,)  # force single value into tuple

                if many:
                    cur.executemany(query, params)
                else:
                    cur.execute(query, params)

                if fetch:
                    return cur.fetchall()
    finally:
        conn.close()


def get_user(username):
    row = run_query(
        "SELECT user_id, username, password_hash, totp_secret FROM seo.users WHERE username = %s;",
        (username,), fetch=True
    )
    if not row:
        return None

    rec = row[0]
    # If it's a dict (RealDictCursor) → use keys
    if isinstance(rec, dict):
        return rec
    # If it's a tuple → unpack manually
    else:
        user_id, uname, pwd_hash, totp_secret = rec
        return {
            "user_id": user_id,
            "username": uname,
            "password_hash": pwd_hash,
            "totp_secret": totp_secret
        }


def update_totp_secret(user_id, secret):
    run_query("UPDATE seo.users SET totp_secret = %s WHERE user_id = %s;", (secret, user_id))


def registration_page():
    st.subheader("📝 User Registration")

    new_username = st.text_input("Choose Username")
    new_password = st.text_input("Choose Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register", key="btn_register"):
        if not new_username or not new_password:
            st.error("⚠️ Username and password required")
        elif new_password != confirm_password:
            st.error("⚠️ Passwords do not match")
        else:
            # Check if username already exists
            exists = run_query("SELECT 1 FROM seo.users WHERE username = %s;", (new_username,), fetch=True)
            if exists:
                st.error("❌ Username already exists!")
                return

            # Hash password
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

            # Generate TOTP secret at registration
            secret = pyotp.random_base32()

            # Insert into DB
            run_query(
                "INSERT INTO seo.users (username, password_hash, totp_secret) VALUES (%s, %s, %s);",
                (new_username, hashed, secret)
            )

            # Generate QR for Google Authenticator
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=new_username, issuer_name="SEO Blog Manager")
            qr = qrcode.make(uri)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")

            st.success("✅ User registered successfully! Now scan the QR code below in Google Authenticator:")
            st.image(buf.getvalue())
            st.info("After scanning, you can log in with your username, password, and OTP.")


def login_page():
    st.subheader("🔑 Login")

    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login", key="btn_login"):
        user = get_user(username)
        if not user:
            st.error("❌ Invalid username")
            return

        db_pwd = user["password_hash"]
        #st.write("DEBUG: Stored hash →", db_pwd)   # 👈 add this
        #st.write("DEBUG: Entered password →", password)  # 👈 add this

        password_ok = False

        if db_pwd:
            try:
                if bcrypt.checkpw(password.encode(), db_pwd.encode()):
                    password_ok = True
            except (ValueError, TypeError) as e:
                st.write("DEBUG: bcrypt error →", str(e))

        if not password_ok:
            st.error("❌ Invalid password")
            return

        # OTP part continues here...

        # ---- OTP Step ----
        st.session_state["awaiting_otp"] = True
        st.session_state["auth_user"] = user
        st.success("✅ Password correct. Please enter OTP.")

    if st.session_state.get("awaiting_otp"):
        otp = st.text_input("Enter 6-digit OTP", max_chars=6, key="otp_input")
        if st.button("Verify OTP", key="btn_verify_otp"):
            user = st.session_state["auth_user"]
            if not user["totp_secret"]:
                st.error("❌ No TOTP secret found. Please re-register.")
                return

            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp):
                st.session_state["authenticated"] = True
                st.session_state["awaiting_otp"] = False
                st.success("🎉 Login successful!")
                st.session_state["page"] = "welcome"
                st.rerun()
                #blog_page()
            else:
                st.error("❌ Invalid OTP")

#def logout_button():
#    if st.sidebar.button("🚪 Logout"):
#        st.session_state["authenticated"] = False
#        st.session_state["auth_user"] = None
#        st.session_state["awaiting_otp"] = False
#        st.success("You have been logged out.")
#        st.stop()
        
def logout_button():
    if st.sidebar.button("🚪 Logout"):
        st.session_state["authenticated"] = False
        st.session_state["auth_user"] = None
        st.session_state["awaiting_otp"] = False
        st.rerun()  # refresh page after logout
        
#def auth_controller():
#    st.sidebar.title("User Access")
#    page = st.sidebar.radio("Select:", ["Login", "Register"])

#    if page == "Register":
#        registration_page()
#    else:
#        login_page()

    # Stop everything until authenticated
#    if not st.session_state["authenticated"]:
#        st.stop()

def auth_controller():
    # If user already logged in
    if st.session_state["authenticated"]:
        user = st.session_state["auth_user"]
        st.sidebar.markdown(f"👋 Hello, **{user['username']}**")
        logout_button()
        return True
    else:
        # Show login/register options
        st.sidebar.title("User Access")
        page = st.sidebar.radio("Select:", ["Login"])
        #page = st.sidebar.radio("Select:", ["Login", "Register"])

        if page == "Register":
            registration_page()
        else:
            login_page()

        # Stop everything until authenticated
        if not st.session_state["authenticated"]:
            st.stop()
        return True

def change_password_page():
    if not st.session_state.get("authenticated", False):
        st.error("⚠️ You must be logged in to change your password.")
        st.stop()

    user = st.session_state["auth_user"]
    st.subheader("🔑 Change Password")

    current_pw = st.text_input("Current Password", type="password", key="current_pw")
    new_pw = st.text_input("New Password", type="password", key="new_pw")
    confirm_pw = st.text_input("Confirm New Password", type="password", key="confirm_pw")

    if st.button("Update Password", key="update_pw_btn"):
        # Verify current password
        stored_hash = user["password_hash"]

        try:
            if stored_hash.startswith("$2b$"):  # bcrypt
                if not bcrypt.checkpw(current_pw.encode(), stored_hash.encode()):
                    st.error("❌ Current password is incorrect")
                    return
            else:
                if current_pw != stored_hash:
                    st.error("❌ Current password is incorrect")
                    return

        except Exception as e:
            st.error(f"⚠️ Error verifying password: {e}")
            return

        # Check new password match
        if new_pw != confirm_pw:
            st.error("❌ New passwords do not match")
            return

        if not new_pw:
            st.error("⚠️ New password cannot be empty")
            return

        # Hash new password
        new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()

        # Update in DB
        run_query("UPDATE seo.users SET password_hash = %s WHERE user_id = %s;", (new_hash, user["user_id"]))

        # Update session copy
        user["password_hash"] = new_hash
        st.session_state["auth_user"] = user

        st.success("✅ Password updated successfully!")


def welcome_page():
    user = st.session_state["auth_user"]
    st.title(f"👋 Welcome, {user['username']}!")
    st.write("You are successfully logged in. Click on the [Add New Blog] button to start managing your blogs.")
    
    #if st.button("➡️ Go to Blog Manager", key="btn_blog_manager"):
    #    st.session_state["page"] = "blog"
    #    st.rerun()
        
def main_controller():
    if not st.session_state["authenticated"]:
        # Show only login/register before authentication
        st.sidebar.title("User Access")
        #page = st.sidebar.radio("Select:", ["Login", "Register"])
        page = st.sidebar.radio("Select:", ["Login"])
        if page == "Register":
            registration_page()
        else:
            login_page()
        st.stop()
    else:
        # After login → sidebar shows hello + logout only
        user = st.session_state["auth_user"]
        st.sidebar.markdown(f"👋 Hello, **{user['username']}**")
        
        if st.sidebar.button("🔑 Change Password"):
            st.session_state["page"] = "change_pw"
            st.rerun()
            
        #if st.sidebar.button("➡️ Go to Blog Manager", key="btn_blog_manager2"):
        #    st.session_state["page"] = "blog"
        #    st.rerun()
        
        if st.sidebar.button("👉 Add New Blog", key="btn_blog_manager2"):
            st.session_state["page"] = "blog"
            st.rerun()
    
        if st.sidebar.button("🚪 Logout"):
            st.session_state["authenticated"] = False
            st.session_state["auth_user"] = None
            st.session_state["awaiting_otp"] = False
            st.session_state["page"] = "welcome"
            st.rerun()

        # Decide which page to show
        if "page" not in st.session_state:
            st.session_state["page"] = "welcome"

        if st.session_state["page"] == "welcome":
            welcome_page()
        
        if st.session_state["page"] == "blog":
            blog_page()
            
        if st.session_state["page"] == "change_pw":
            change_password_page()
        
# ------------------- MAIN ------------------- #
#if not st.session_state["authenticated"]:
#    registration_page()
#    st.stop()

#if auth_controller():  # Only continue if logged in
#    user = st.session_state["auth_user"]
#    st.write(f"### 👋 Welcome, {user['username']}!")
    
# Run auth first
#auth_controller()

# If logged in, show logout
#logout_button()




def blog_page():
    user = st.session_state["auth_user"]

    # Sidebar greeting + logout only
    #st.sidebar.markdown(f"👋 Hello, **{user['username']}**")
    #if st.sidebar.button("🚪 Logout", key="btn_logout"):
    #    st.session_state["authenticated"] = False
    #    st.session_state["auth_user"] = None
    #    st.session_state["awaiting_otp"] = False
    #    st.rerun()
        
        
    # ------------------- SIDEBAR SEARCH ------------------- #

    #st.sidebar.title("Blog Management")
    #action = st.sidebar.radio("Select Action:", ("Add New Blog Details", "View Existing Blog Details"))

    # Clear all input fields
    for key in ["topic", "title", "meta_desc", "url", "category_name", "product", "primary_kw",
                        "subcategories", "secondary_kws", "inbound_links", "lst_values"]:
        if key in st.session_state:
            if isinstance(st.session_state[key], list):
                st.session_state[key] = [""]
            else:
                st.session_state[key] = ""        
        
    st.sidebar.header("🔍 Search Blog by Primary Keyword")

    search_kw = st.sidebar.text_input("Enter Primary Keyword")

    if search_kw:
        results = run_query("""
        SELECT title_name, url 
        FROM seo.tbl_blog_mst 
        where primary_kw_id in 
        (    
            select distinct primary_kw_id 
            from 
            (     
                SELECT primary_keyword, primary_kw_id 
                FROM seo.tbl_primary_kw_mst 
                WHERE primary_keyword ILIKE %s
                UNION
                SELECT secondary_kw_name, primary_kw_id  
                FROM seo.tbl_secondary_kw_mst
                WHERE secondary_kw_name ILIKE %s
            )
        );""", (f"%{search_kw}%", f"%{search_kw}%"), fetch=True)

        if results:
            st.sidebar.success(f"Found {len(results)} result(s)")

            # Table view
            #result_df = pd.DataFrame(results, columns=["Title", "URL"])
            #st.sidebar.dataframe(result_df)
            
            result_df = pd.DataFrame(results)
            #result_df = result_df.rename(columns={"title_name": "Title","url": "URL"})
            result_df = result_df.rename(columns={"title_name": "Title"})
            st.sidebar.dataframe(result_df)
            

            # Clickable links
            #st.sidebar.markdown("### 🔗 Quick Links")
            #for row in results:
                #primary_kw, url = row
                #st.sidebar.markdown(f"- **{primary_kw}** → [Open Blog]({url})", unsafe_allow_html=True)
        else:
            st.sidebar.warning("No blogs found for this keyword.")

    # ------------------- DB FUNCTIONS ------------------- #
    def get_categories():
        return run_query(
            "SELECT category_id, category_name FROM seo.tbl_category_mst ORDER BY category_name;", 
            fetch=True
        )

    def get_subcategories(category_id):
        return run_query(
            "SELECT subcategory_id, subcategory_name FROM seo.tbl_subcategory_mst WHERE category_id = %s;", 
            (category_id,), 
            fetch=True
        )

    def check_primary_keyword_exists(primary_keyword):
        rows = run_query("""
            SELECT 1 FROM seo.tbl_primary_kw_mst WHERE LOWER(primary_keyword) = LOWER(%s)
            UNION
            SELECT 1 FROM seo.tbl_secondary_kw_mst WHERE LOWER(secondary_kw_name) = LOWER(%s);
        """, (primary_keyword, primary_keyword), fetch=True)
        return bool(rows)

    def check_category_exists(category_name):
        rows = run_query("""
            SELECT 1 FROM seo.tbl_category_mst WHERE LOWER(category_name) = LOWER(%s);
        """, (category_name), fetch=True)
        return bool(rows)
        
    def insert_blog(topic, title, meta_desc, url, category_name, subcategory_ids, product, inbound_links, primary_kw, secondary_kws, lst_values):
            
        # Primary keyword
        pk_row = run_query("""SELECT primary_kw_id FROM seo.tbl_primary_kw_mst WHERE primary_keyword=%s;""", (primary_kw,), fetch=True)
        if pk_row:
            #primary_kw_id = pk_row[0][0]
            primary_kw_id = pk_row[0]["primary_kw_id"]
        else:
            pk_row = run_query(
                """INSERT INTO seo.tbl_primary_kw_mst (primary_keyword) VALUES (%s) RETURNING primary_kw_id;""",
                (primary_kw,), fetch=True
            )
            primary_kw_id = pk_row[0]["primary_kw_id"]
            
        #st.write("pk_row:", pk_row)
        #if pk_row and len(pk_row) > 0 and len(pk_row[0]) > 0:
        #    primary_kw_id = pk_row[0][0]
        #    print("DEBUG primary_kw_id:", primary_kw_id)
        #else:
        #    raise ValueError(f"Primary keyword insert failed. pk_row={pk_row}")
            
            #primary_kw_id = pk_row[0][0]

        # --- Category Lookup / Insert ---
        cat_row = run_query("""SELECT category_id FROM seo.tbl_category_mst WHERE category_name = %s;""", (category_name,), fetch=True)
        if cat_row:
            category_id = cat_row[0]["category_id"]
        else:
            cat_row = run_query(
                """INSERT INTO seo.tbl_category_mst (category_name) VALUES (%s) RETURNING category_id;""",
                (category_name,), fetch=True
            )
            category_id = cat_row[0]["category_id"]

        # --- Insert Blog ---
        blog_row = run_query("""
            INSERT INTO seo.tbl_blog_mst (topic_name, title_name, meta_description, url, category_id, product_name, primary_kw_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            RETURNING blog_id;
        """, (topic, title, meta_desc, url, category_id, product, primary_kw_id), fetch=True)
        blog_id = blog_row[0]["blog_id"]

        # --- Secondary Keywords ---
        if secondary_kws:
            for skw in secondary_kws:
                if skw.strip():
                    run_query("""
                        INSERT INTO seo.tbl_secondary_kw_mst (secondary_kw_name, primary_kw_id)
                        VALUES (%s,%s);
                    """, (skw.strip(), primary_kw_id))
        
        # --- SubCategories ---
        if subcategory_ids:
            for subcat in subcategory_ids:
                if subcat.strip():
                    run_query("""
                        INSERT INTO seo.tbl_subcategory_mst (subcategory_name, category_id)
                        VALUES (%s,%s);
                    """, (subcat.strip(), category_id))
                    
        # --- Inbound Links ---
        if inbound_links:
            for link in inbound_links:
                if link.strip():
                    run_query(
                        "INSERT INTO seo.tbl_inbound_links (blog_id, inbound_link_url) VALUES (%s,%s);", 
                        (blog_id, link.strip())
                    )

        # --- LST ---
        if lst_values:
            for lst in lst_values:
                if lst.strip():
                    run_query(
                        "INSERT INTO seo.tbl_lst (blog_id, lst) VALUES (%s,%s);", 
                        (blog_id, lst.strip())
                    )

        return blog_id


    def get_blogs():
        return run_query("""
            SELECT b.blog_id, b.topic_name, b.title_name, b.meta_description, b.url, c.category_name, b.product_name, pk.primary_keyword,
                   --skw.secondary_kw_name, cs.subcategory_name, ls.lst, ib.inbound_link_url
                    STRING_AGG(DISTINCT skw.secondary_kw_name, ', ') AS secondary_keywords,
                    STRING_AGG(DISTINCT cs.subcategory_name, ', ') AS subcategories,
                    STRING_AGG(DISTINCT ls.lst, ', ') AS lst_values,
                    STRING_AGG(DISTINCT ib.inbound_link_url, ', ') AS inbound_links
            FROM seo.tbl_blog_mst b
            LEFT JOIN seo.tbl_category_mst c ON b.category_id = c.category_id
            LEFT JOIN seo.tbl_primary_kw_mst pk ON b.primary_kw_id = pk.primary_kw_id
            LEFT JOIN seo.tbl_secondary_kw_mst skw ON skw.primary_kw_id = pk.primary_kw_id
            LEFT JOIN seo.tbl_subcategory_mst cs ON cs.category_id = c.category_id
            LEFT JOIN seo.tbl_lst ls ON ls.blog_id = b.blog_id
            LEFT JOIN seo.tbl_inbound_links ib ON ib.blog_id = b.blog_id
            GROUP BY b.blog_id, b.topic_name, b.title_name, b.meta_description, b.url, c.category_name, b.product_name, pk.primary_keyword
            ORDER BY b.blog_id DESC;
        """, fetch=True)

    def delete_blog(blog_id):
        run_query("DELETE FROM seo.tbl_blog_mst WHERE blog_id = %s;", (blog_id,))

    # ------------------- STREAMLIT UI ------------------- #
    st.title("Blog Data Entry Form")

    # State initialization
    for key in ["subcategories", "secondary_kws", "inbound_links", "lst_values"]:
        if key not in st.session_state:
            st.session_state[key] = [""]
                        
    # Input fields
    topic = st.text_input("**Topic**", key="topic")
    title = st.text_input("**Title**", key="title")
    meta_desc = st.text_area("**Meta Description**", key="meta_desc")
    url = st.text_input("**URL**", key="url")

    #categories = get_categories()
    #cat_map = {name: cid for cid, name in categories}
    #category_name = st.text_input("Category", [""] + list(cat_map.keys()))
    category_name = st.text_input("**Category**", key="category_name")
    #category_id = cat_map.get(category_name)

    # Subcategories
    st.markdown("**SubCategories**")
    for i, val in enumerate(st.session_state["subcategories"]):
        cols = st.columns([6,1,1])
        st.session_state["subcategories"][i] = cols[0].text_input(f"SubCategory {i+1}", value=val, key=f"subcat_{i}")
        if cols[1].button("➕ Add", key=f"add_subcat_{i}"):
            st.session_state["subcategories"].append("")
        if cols[2].button("🗑️", key=f"del_subcat_{i}") and len(st.session_state["subcategories"]) > 1:
            st.session_state["subcategories"].pop(i)
            st.rerun()

    product = st.text_input("**Product**", key="product")

    # Inbound Links
    st.markdown("**Inbound Links**")
    for i, val in enumerate(st.session_state["inbound_links"]):
        cols = st.columns([6,1,1])
        st.session_state["inbound_links"][i] = cols[0].text_input(f"Inbound Link {i+1}", value=val, key=f"inbound_{i}")
        if cols[1].button("➕ Add", key=f"add_inbound_{i}"):
            st.session_state["inbound_links"].append("")
        if cols[2].button("🗑️", key=f"del_inbound_{i}") and len(st.session_state["inbound_links"]) > 1:
            st.session_state["inbound_links"].pop(i)
            st.rerun()

    primary_kw = st.text_input("**Primary Keyword**", key="primary_kw")

    # Secondary Keywords
    st.markdown("**Secondary Keywords**")
    for i, val in enumerate(st.session_state["secondary_kws"]):
        cols = st.columns([6,1,1])
        st.session_state["secondary_kws"][i] = cols[0].text_input(f"Secondary Keyword {i+1}", value=val, key=f"skw_{i}")
        if cols[1].button("➕ Add", key=f"add_skw_{i}"):
            st.session_state["secondary_kws"].append("")
        if cols[2].button("🗑️", key=f"del_skw_{i}") and len(st.session_state["secondary_kws"]) > 1:
            st.session_state["secondary_kws"].pop(i)
            st.rerun()

    # LST
    st.markdown("**LST Values**")
    for i, val in enumerate(st.session_state["lst_values"]):
        cols = st.columns([6,1,1])
        st.session_state["lst_values"][i] = cols[0].text_input(f"LST {i+1}", value=val, key=f"lst_{i}")
        if cols[1].button("➕ Add", key=f"add_lst_{i}"):
            st.session_state["lst_values"].append("")
        if cols[2].button("🗑️", key=f"del_lst_{i}") and len(st.session_state["lst_values"]) > 1:
            st.session_state["lst_values"].pop(i)
            st.rerun()

    # Preview

    #st.subheader("Preview Entry")
    #preview_df = pd.DataFrame({
    #    "Topic": [topic],
    #    "Title": [title],
    #    "Meta Description": [meta_desc],
    #    "URL": [url],
    #    "Category": [category_name],
    #    "SubCategories": [", ".join(st.session_state["subcategories"])],
    #    "Product": [product],
    #    "Inbound Links": [", ".join(st.session_state["inbound_links"])],
    #    "Primary Keyword": [primary_kw],
    #    "Secondary Keywords": [", ".join(st.session_state["secondary_kws"])],
    #    "LST": [", ".join(st.session_state["lst_values"])]
    #})
    #st.dataframe(preview_df)
      


    # Save
    if st.button("Save Blog", key="btn_save_blog"):
        if not topic or not title or not primary_kw:
            st.error("Topic, Title and Primary Keyword are required.")
        elif check_primary_keyword_exists(primary_kw):
            st.error("Primary keyword already exists. Please change it.")
        #elif check_category_exists(category_name):
        #    st.error("Category already exists. Please change it.")
        else:
            insert_blog(
                topic, title, meta_desc, url, category_name,
                st.session_state["subcategories"], product,
                st.session_state["inbound_links"], primary_kw,
                st.session_state["secondary_kws"], st.session_state["lst_values"]
            )
            st.success("Blog saved successfully!")
            
            
            # Reset form
            st.session_state["subcategories"] = [""]
            st.session_state["secondary_kws"] = [""]
            st.session_state["inbound_links"] = [""]
            st.session_state["lst_values"] = [""]
            

    # Show saved blogs
    st.subheader("Existing Blogs")
    blogs = get_blogs()
    if blogs:
        #blog_df = pd.DataFrame(
        #    blogs, 
        #    columns=["ID","Topic","Title","Meta Description","URL","Category","Product","Primary Keyword"]
        #)
        #st.dataframe(blog_df)
        
        blog_df = pd.DataFrame(blogs)
        blog_df = blog_df.reset_index(drop=True)
        
        blog_df = blog_df.rename(columns={
            "blog_id": "ID",
            "topic_name": "Topic",
            "title_name": "Title",
            "meta_description": "Meta Description",
            "url": "URL",
            "category_name": "Category",
            "subcategories": "SubCategory",
            "product_name": "Product",
            "inbound_links" : "Inbound Links",
            "primary_keyword": "Primary Keyword",
            "secondary_keywords": "Secondary Keyword",
            "lst_values": "LST"
        })
        blog_df.insert(0, "S.No", range(1, len(blog_df) + 1))
        
              
        st.dataframe(blog_df[["Topic","Title","Meta Description","URL","Category","SubCategory","Product","Inbound Links","Primary Keyword","Secondary Keyword","LST"]].reset_index(drop=True))
        
        #blog_df_display = blog_df[["Topic","Title","Meta Description","URL","Category","SubCategory",
        #                       "Product","Inbound Links","Primary Keyword","Secondary Keyword","LST"]].reset_index(drop=True)

        # Display without the index
        #st.dataframe(blog_df_display)
        
        st.markdown("---")  # Separator
        
        # Add Delete buttons row-wise
        for i, row in blog_df.iterrows():
            cols = st.columns([8, 1])
            with cols[0]:
                st.write(f"**{row['S.No']} : {row['Title']}**")
            with cols[1]:
                if st.button("Delete", key=f"del_blog_{row['ID']}"):
                    delete_blog(row["ID"])
                    st.warning(f"Blog {row['ID']} deleted.")
                    st.rerun()
    else:
        st.info("No blogs found.")

        # Delete actions
        #for row in blog_df.itertuples():
        #    col1, col2 = st.columns([8,1])
        #    with col1:
        #        st.write(f"**{row.Topic} : {row.Title}**")
        #    with col2:
        #        if st.button("Delete", key=f"del_blog_{row.ID}"):
        #            delete_blog(row.ID)
        #            st.warning(f"Blog {row.ID} deleted.")
        #            st.rerun()

        #for i, row in enumerate(blog_df.itertuples(), start=1):
        #    col1, col2 = st.columns([8, 1])
        #    with col1:
        #        st.write(f"**{i} : {row.Title}**")  # Serial number instead of ID
        #    with col2:
        #        if st.button("Delete", key=f"del_blog_{row.ID}"):
        #            delete_blog(row.ID)  # actual DB deletion uses ID
        #            st.warning(f"Blog {row.ID} deleted.")
        #            st.experimental_rerun()  # refresh page
    

        
main_controller()
