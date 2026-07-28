import sys
import asyncio
import multiprocessing
import uvicorn
from streamlit.web import cli as stcli

def start_backend():
    # Enforce Windows loop policy inside the child process if on Windows
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    uvicorn.run(
        "backendAPI:app",
        host="0.0.0.0",
        port=8000,
        loop="asyncio",
        reload=False,
    )

def start_frontend():
    # Programmatically run: streamlit run streamlit_ui.py
    sys.argv = ["streamlit", "run", "streamlit_ui.py"]
    sys.exit(stcli.main())

if __name__ == "__main__":
    # 1. Start FastAPI in a background process
    backend_process = multiprocessing.Process(target=start_backend, daemon=True)
    backend_process.start()

    # 2. Start Streamlit in the main thread
    try:
        start_frontend()
    except KeyboardInterrupt:
        print("Shutting down servers...")
    finally:
        # Clean up the backend process when Streamlit exits
        if backend_process.is_alive():
            backend_process.terminate()
            backend_process.join()


    #Script to add keywords to database
    '''-------------------------------------------------------------------------------------------------------
    from db.database import add_bulk_keywords
    
    keywords = [("access", "urgency", 0.2),
                ("accounts", "account", 0.2),
                ("security", "urgency", 0.6),
                ("portal", "account", 0.2),
                ("user", "account", 0.4),
                ("company", "account", 0.3),
                ("admin", "account", 0.6),
                ("credential", "urgency", 0.6),
                ("identity", "urgency", 0.8),
                ("login", "urgency", 0.9),
                ("password", "urgency", 0.9),
                ("privilege", "urgency", 0.6),
                ("token", "urgency", 0.2),
                ("validation", "urgency", 0.8),
                ("assurance", "urgency", 0.4),
                ("availability", "urgency", 0.2),
                ("confidentiality", "urgency", 0.5),
                ("integrity", "urgency", 0.6),
                ("privacy", "urgency", 0.8),
                ("safety", "urgency", 0.9),
                ("trust", "urgency", 0.6),
                ("verification", "urgency", 0.7),
                ("check", "urgency", 0.4),
                ("key", "urgency", 0.2),
                ("lock", "urgency", 0.6),
                ("biometrics", "urgency", 0.2),
                ("authorize", "urgency", 0.8),
                ("authentication", "urgency", 0.9),
                ("session", "urgency", 0.4),
                ("verification", "urgency", 0.5),
                ("profile", "account", 0.2),
                ("service", "urgency", 0.2),
                ("support", "urgency", 0.2),
                ("notify", "account", 0.2),
                ("email", "account", 0.6),
                ("account", "account", 0.2),
                ("update", "urgency", 0.6),
                ("secure", "urgency", 0.8),
                ("notification", "urgency", 0.2),
                ("transaction", "financial", 0.55),
                ("validate", "account", 0.5),
                ("confirmation", "urgency", 0.7),
                ("manager", "infrastructure", 0.6),
                ("assistant", "infrastructure", 0.2),
                ("dashboard", "account", 0.2),
                ("information", "account", 0.76),
                ("communication", "urgency", 0.2),
                ("finance", "financial", 0.7),
                ("maintenance", "urgency", 0.3),
                ("service", "urgency", 0.4),
                ("customer", "urgency", 0.2),
                ("invoice", "financial", 0.8),
                ("billing", "financial", 0.8),
                ("transaction", "financial", 0.8),
                ("subscription", "financial", 0.75),
                ("order", "financial", 0.9),
                ("shipment", "financial", 0.8),
                ("purchase", "financial", 0.9),
                ("support", "urgency", 0.3),
                ("notification", "urgency", 0.2),
                ("alert", "urgency", 0.9),
                ("confirmation", "financial", 0.2),
                ("billinginfo", "financial", 0.9),
                ("receipt", "financial", 0.8),
                ("accountinfo", "account", 0.7),
                ("profile", "account", 0.4),
                ("payment", "financial", 0.95),
                ("invoiceinfo", "financial", 0.5),
                ("orderinfo", "financial", 0.5),
                ("youtube", "brand", 0.9),
                ("facebook", "brand", 0.9),
                ("instagram", "brand", 0.9),
                ("amazon", "brand", 0.9),
                ("reddit", "brand", 0.9),
                ("x", "brand", 0.9),
                ("whatsapp", "brand", 0.9),
                ("tiktok", "brand", 0.9),
                ("linkedin", "brand", 0.9),
                ("netflix", "brand", 0.9),
                ("pinterest", "brand", 0.9),
                ("microsoft", "brand", 0.9),
                ("temu", "brand", 0.9),
                ("twitch", "brand", 0.9),
                ("canva", "brand", 0.9),
                ("fandom", "brand", 0.9),
                ("samsung", "brand", 0.9),
                ("telegram", "brand", 0.9),
                ("git", "brand", 0.9),
                ("github", "brand", 0.9),
                ("spotify", "brand", 0.9),
                ("imdb", "brand", 0.9),
                ("paypal", "brand", 0.9),
                ("apple", "brand", 0.9),
                ("roblox", "brand", 0.9),
                ("aliexpress", "brand", 0.9),
                ("openai", "brand", 0.9),
                ("ebay", "brand", 0.9),
                ("walmart", "brand", 0.9),
                ("nytimes", "brand", 0.9),
                ]
    add_bulk_keywords(keywords)
_________________________________________________________________________________________________________'''
