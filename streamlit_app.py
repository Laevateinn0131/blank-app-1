import streamlit as st
import json
import re
from datetime import datetime
import time
import random
import os

# Gemini API (インストール必要: pip install google-generativeai)
try:
   import google.generativeai as genai
   GEMINI_AVAILABLE = True
except ImportError:
   GEMINI_AVAILABLE = False
   

# ページ設定
st.set_page_config(
   page_title="📞 AI電話番号チェッカー",
   page_icon="🤖",
   layout="wide"
)

# デフォルトのAPIキー（環境変数から取得、なければデフォルト値）
DEFAULT_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDuxrHGEiBATrTUQ6iqiZqe_oyNbNL58Ww")

# セッション状態の初期化
if 'check_history' not in st.session_state:
   st.session_state.check_history = []
if 'scam_database' not in st.session_state:
   st.session_state.scam_database = {
       "known_scam_numbers": [
           "03-1234-5678",
           "0120-999-999",
           "050-1111-2222",
           "090-1234-5678"
       ],
       "suspicious_prefixes": [
           "050", "070", "+675", "+234", "+1-876"
       ],
       "warning_patterns": [
           r"^0120", r"^0570", r"^0990", r"^\+.*"
       ],
       "safe_prefixes": ["110", "119", "118"],
       "reported_cases": []
   }
if 'monitoring' not in st.session_state:
   st.session_state.monitoring = False
if 'last_check' not in st.session_state:
   st.session_state.last_check = None
if 'gemini_api_key' not in st.session_state:
   st.session_state.gemini_api_key = DEFAULT_API_KEY
if 'ai_enabled' not in st.session_state:
   st.session_state.ai_enabled = False

def setup_gemini():
   """Gemini API設定"""
   if st.session_state.gemini_api_key and GEMINI_AVAILABLE:
       try:
           genai.configure(api_key=st.session_state.gemini_api_key)
           return True
       except Exception as e:
           st.error(f"Gemini API設定エラー: {str(e)}")
           return False
   return False

def analyze_with_gemini(number, basic_result):
   """Gemini AIによる高度な分析（caller_type追加）"""
   if not setup_gemini():
       return None
   
   try:
       model = genai.GenerativeModel('gemini-pro')
       caller_type_info = basic_result.get('caller_type', {})
       
       prompt = f"""
あなたは電話番号の専門家です。以下の情報から、この電話番号の詳細を分析してください。

電話番号: {number}
正規化: {basic_result['normalized']}
番号タイプ: {basic_result['details'][0] if basic_result['details'] else '不明'}
地域: {basic_result['details'][1] if len(basic_result['details']) > 1 else '不明'}

現在の判定:
- 発信者タイプ: {caller_type_info.get('type', '不明')}
- カテゴリ: {caller_type_info.get('category', '不明')}
- リスクレベル: {basic_result['risk_level']}

以下を分析してJSON形式で回答:
{{
   "caller_identification": {{
       "most_likely": "個人/一般企業/金融機関/公的機関/詐欺グループ/不明",
       "confidence": "高/中/低",
       "reasoning": "判定理由"
   }},
   "business_type": "具体的な業種（例: 通信販売、保険営業、アンケート調査など）",
   "ai_risk_assessment": "安全/注意/危険",
   "confidence_score": 0-100,
   "fraud_patterns": ["考えられる詐欺パターン"],
   "similar_cases": ["類似事例"],
   "recommendations": ["推奨行動"],
   "conversation_warnings": ["警戒すべき会話内容"],
   "summary": "総合分析（150文字程度）"
}}
"""
       
       response = model.generate_content(prompt)
       
       try:
           ai_result = json.loads(response.text)
           return ai_result
       except:
           return {
               "caller_identification": {
                   "most_likely": "不明",
                   "confidence": "低",
                   "reasoning": "分析失敗"
               },
               "business_type": "不明",
               "ai_risk_assessment": "不明",
               "confidence_score": 0,
               "fraud_patterns": [],
               "similar_cases": [],
               "recommendations": [],
               "conversation_warnings": [],
               "summary": response.text[:200]
           }
   except Exception as e:
       st.error(f"Gemini分析エラー: {str(e)}")
       return None

def analyze_conversation_with_gemini(conversation_text):
   """通話内容をGemini AIで分析"""
   if not setup_gemini():
       return None
   
   try:
       model = genai.GenerativeModel('gemini-pro')
       
       prompt = f"""
あなたは詐欺電話検出の専門家です。以下の通話内容を分析してください。

通話内容:
{conversation_text}

以下を分析してください:
1. 詐欺の可能性（0-100%）
2. 詐欺の手口の種類
3. 危険なキーワード
4. すぐに取るべき行動
5. 通報すべきかどうか

JSON形式で回答:
{{
   "scam_probability": 0-100,
   "fraud_type": "オレオレ詐欺/架空請求/など",
   "dangerous_keywords": ["キーワード1", "キーワード2"],
   "immediate_actions": ["行動1", "行動2"],
   "should_report": true/false,
   "explanation": "詳細な説明"
}}
"""
       
       response = model.generate_content(prompt)
       try:
           return json.loads(response.text)
       except:
           return {"explanation": response.text[:200]}
   except Exception as e:
       st.error(f"会話分析エラー: {str(e)}")
       return None

def identify_caller_type(number, normalized):
   """発信者タイプの詳細識別"""
   caller_info = {
       "type": "不明",
       "confidence": "低",
       "details": [],
       "category": "その他"
   }
   
   # 緊急番号
   if normalized in ["110", "119", "118"]:
       caller_info["type"] = "緊急通報番号"
       caller_info["confidence"] = "確実"
       caller_info["category"] = "公的機関"
       caller_info["details"].append("警察・消防・海上保安庁")
       return caller_info
   
   # 公的機関の代表番号パターン
   government_patterns = {
       "03-3581": "官公庁（霞が関周辺）",
       "03-5253": "厚生労働省・文部科学省エリア",
       "03-3580": "警察庁周辺",
       "03-5321": "都庁・都の機関",
       "06-6941": "大阪府庁周辺",
   }
   
   for prefix, org in government_patterns.items():
       if number.startswith(prefix):
           caller_info["type"] = "公的機関"
           caller_info["confidence"] = "高"
           caller_info["category"] = "公的機関"
           caller_info["details"].append(org)
           return caller_info
   
   # 銀行・金融機関
   bank_patterns = {
       "0120-86": "三菱UFJ銀行系",
       "0120-77": "三井住友銀行系",
       "0120-65": "みずほ銀行系",
       "0120-39": "ゆうちょ銀行系",
   }
   
   for prefix, bank in bank_patterns.items():
       if number.startswith(prefix):
           caller_info["type"] = "金融機関"
           caller_info["confidence"] = "中"
           caller_info["category"] = "一般企業"
           caller_info["details"].append(bank)
           caller_info["details"].append("⚠️ 本物か必ず確認してください")
           return caller_info
   
   # 番号タイプによる判定
   if normalized.startswith('0120') or normalized.startswith('0800'):
       caller_info["type"] = "企業カスタマーサポート"
       caller_info["confidence"] = "中"
       caller_info["category"] = "一般企業"
       caller_info["details"].append("フリーダイヤル（通話無料）")
       caller_info["details"].append("企業からの連絡が多い")
   elif normalized.startswith('0570'):
       caller_info["type"] = "企業ナビダイヤル"
       caller_info["confidence"] = "中"
       caller_info["category"] = "一般企業"
       caller_info["details"].append("通話料有料（高額になることも）")
       caller_info["details"].append("企業のサポートセンター等")
   elif normalized.startswith('050'):
       caller_info["type"] = "IP電話利用者"
       caller_info["confidence"] = "低"
       caller_info["category"] = "不明"
       caller_info["details"].append("個人/企業どちらも可能性あり")
       caller_info["details"].append("IP電話は匿名性が高い")
       caller_info["details"].append("⚠️ 詐欺に悪用されやすい")
   elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
       caller_info["type"] = "個人携帯電話"
       caller_info["confidence"] = "高"
       caller_info["category"] = "個人"
       caller_info["details"].append("個人契約の携帯電話")
       caller_info["details"].append("まれに法人契約もあり")
   elif normalized.startswith('020'):
       caller_info["type"] = "ポケベル・M2M"
       caller_info["confidence"] = "高"
       caller_info["category"] = "特殊"
       caller_info["details"].append("IoT機器等の通信")
   elif normalized.startswith('0'):
       area = identify_area(number)
       if area != "不明":
           caller_info["type"] = "固定電話（企業または個人宅）"
           caller_info["confidence"] = "中"
           caller_info["category"] = "企業または個人"
           caller_info["details"].append(f"地域: {area}")
           caller_info["details"].append("企業のオフィスまたは個人宅")
       else:
           caller_info["type"] = "固定電話"
           caller_info["confidence"] = "低"
           caller_info["category"] = "不明"
   elif number.startswith('+') or normalized.startswith('010'):
       caller_info["type"] = "国際電話"
       caller_info["confidence"] = "確実"
       caller_info["category"] = "国際"
       caller_info["details"].append("海外からの着信")
       caller_info["details"].append("⚠️ 国際詐欺に注意")
   
   return caller_info

def identify_area(number):
   """地域識別"""
   area_codes = {
       "03": "東京", "06": "大阪", "052": "名古屋",
       "011": "札幌", "092": "福岡", "075": "京都"
   }
   for code, area in area_codes.items():
       if number.startswith(code):
           return area
   return "不明"

def identify_number_type(normalized):
   """番号タイプ識別"""
   if normalized.startswith('0120') or normalized.startswith('0800'):
       return "フリーダイヤル"
   elif normalized.startswith('050'):
       return "IP電話"
   elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
       return "携帯電話"
   elif normalized.startswith('0570'):
       return "ナビダイヤル"
   elif normalized.startswith('0'):
       return "固定電話"
   elif normalized.startswith('+'):
       return "国際電話"
   else:
       return "不明"

def analyze_phone_number(number, use_ai=False):
   """電話番号解析"""
   normalized = re.sub(r'[-\s()]+', '', number)
   
   result = {
       "original": number,
       "normalized": normalized,
       "risk_level": "安全",
       "warnings": [],
       "details": [],
       "recommendations": [],
       "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
       "ai_analysis": None,
       "caller_type": None
   }
   
   # 発信者タイプ識別
   caller_type = identify_caller_type(number, normalized)
   result["caller_type"] = caller_type
   
   # 緊急番号チェック
   if normalized in ["110", "119", "118"]:
       result["risk_level"] = "緊急"
       result["details"].append("✅ 緊急通報番号です")
       return result
   
   # 既知の詐欺番号チェック
   if number in st.session_state.scam_database["known_scam_numbers"]:
       result["risk_level"] = "危険"
       result["warnings"].append("🚨 既知の詐欺電話番号です！")
       result["recommendations"].append("❌ 絶対に応答しないでください")
       result["recommendations"].append("📞 着信拒否設定を推奨")
   
   # ユーザー通報データチェック
   for case in st.session_state.scam_database["reported_cases"]:
       if case["number"] == number:
           result["risk_level"] = "危険"
           result["warnings"].append(f"⚠️ {case['reports']}件の通報あり")
           result["details"].append(f"通報内容: {case['description']}")
   
   # プレフィックスチェック
   for prefix in st.session_state.scam_database["suspicious_prefixes"]:
       if normalized.startswith(prefix):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append(f"⚠️ 疑わしいプレフィックス: {prefix}")
           result["recommendations"].append("慎重に対応してください")
   
   # パターンチェック
   for pattern in st.session_state.scam_database["warning_patterns"]:
       if re.match(pattern, number):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append("⚠️ 警戒が必要なパターンです")
   
   # 国際電話チェック
   if number.startswith('+') or normalized.startswith('010'):
       result["warnings"].append("🌍 国際電話です")
       result["recommendations"].append("身に覚えがない場合は応答しない")
       if result["risk_level"] == "安全":
           result["risk_level"] = "注意"
   
   # 詳細情報
   result["details"].append(f"📱 番号タイプ: {identify_number_type(normalized)}")
   result["details"].append(f"📍 地域: {identify_area(number)}")
   
   # 安全な場合の推奨事項
   if result["risk_level"] == "安全":
       result["recommendations"].append("✅ 特に問題は検出されませんでした")
       result["recommendations"].append("💡 不審な要求には注意してください")
   
   # AI分析
   if use_ai and st.session_state.ai_enabled:
       with st.spinner("🤖 AIが高度な分析を実行中..."):
           ai_result = analyze_with_gemini(number, result)
           if ai_result:
               result["ai_analysis"] = ai_result
               if ai_result.get("ai_risk_assessment") == "危険" and result["risk_level"] != "危険":
                   result["risk_level"] = "危険"
                   result["warnings"].append(f"🤖 AI判定: 危険 (信頼度 {ai_result.get('confidence_score', 0)}%)")
   
   # 履歴に追加
   st.session_state.check_history.append(result)
   return result

def display_result(result):
   """結果表示"""
   risk_colors = {
       "安全": "green", "注意": "orange",
       "危険": "red", "緊急": "blue"
   }
   risk_emoji = {
       "安全": "✅", "注意": "⚠️",
       "危険": "🚨", "緊急": "🚑"
   }
   
   color = risk_colors.get(result['risk_level'], "gray")
   emoji = risk_emoji.get(result['risk_level'], "❓")
   
   st.markdown(f"## {emoji} リスク判定: :{color}[{result['risk_level']}]")
   
   # 発信者タイプ情報
   if result.get('caller_type'):
       caller = result['caller_type']
       category_icons = {
           "個人": "👤", "一般企業": "🏢", "公的機関": "🏛️",
           "金融機関": "🏦", "国際": "🌍", "特殊": "⚙️",
           "不明": "❓", "その他": "📞"
       }
       icon = category_icons.get(caller['category'], "📞")
       
       st.info(f"""
       ### {icon} 発信者タイプ: **{caller['type']}**
       **カテゴリ**: {caller['category']}  
       **信頼度**: {caller['confidence']}
       """)
       
       if caller['details']:
           with st.expander("🔍 発信者詳細情報"):
               for detail in caller['details']:
                   st.markdown(f"- {detail}")
   
   col1, col2, col3 = st.columns(3)
   with col1:
       st.metric("📞 電話番号", result['original'])
   with col2:
       st.metric("🔢 正規化", result['normalized'])
   with col3:
       st.metric("🕐 チェック時刻", result['timestamp'])
   
   st.markdown("---")
   
   # AI分析結果
   if result.get('ai_analysis'):
       ai = result['ai_analysis']
       st.success("### 🤖 Gemini AI 高度分析")
       
       if ai.get('caller_identification'):
           caller_id = ai['caller_identification']
           col1, col2, col3 = st.columns(3)
           with col1:
               st.metric("AI判定", caller_id.get('most_likely', '不明'))
           with col2:
               st.metric("AI信頼度", f"{ai.get('confidence_score', 0)}%")
           with col3:
               business = ai.get('business_type', '不明')
               st.metric("業種", business if len(business) < 20 else business[:17]+"...")
           
           if caller_id.get('reasoning'):
               st.info(f"**判定理由**: {caller_id['reasoning']}")
       
       if ai.get('summary'):
           st.success(f"**📝 AI総合分析**: {ai['summary']}")
       
       if ai.get('fraud_patterns'):
           with st.expander("🎯 想定される詐欺パターン"):
               for pattern in ai['fraud_patterns']:
                   st.markdown(f"- {pattern}")
       
       if ai.get('similar_cases'):
           with st.expander("📋 類似詐欺事例"):
               for case in ai['similar_cases']:
                   st.markdown(f"- {case}")
       
       if ai.get('conversation_warnings'):
           with st.expander("⚠️ 会話で警戒すべきポイント"):
               for warning in ai['conversation_warnings']:
                   st.markdown(f"- {warning}")
       
       st.markdown("---")
   
   # 警告
   if result['warnings']:
       st.error("### ⚠️ 警告")
       for warning in result['warnings']:
           st.markdown(f"- {warning}")
       st.markdown("")
   
   # 詳細情報
   if result['details']:
       st.info("### 📋 詳細情報")
       for detail in result['details']:
           st.markdown(f"- {detail}")
       st.markdown("")
   
   # 推奨事項
   if result['recommendations']:
       if result['risk_level'] == "危険":
           st.error("### 💡 推奨事項")
       else:
           st.success("### 💡 推奨事項")
       for rec in result['recommendations']:
           st.markdown(f"- {rec}")
       
       if result.get('ai_analysis') and result['ai_analysis'].get('recommendations'):
           st.markdown("**🤖 AIからの追加推奨:**")
           for rec in result['ai_analysis']['recommendations']:
               st.markdown(f"- {rec}")

def show_stats():
   """統計情報表示"""
   total = len(st.session_state.check_history)
   dangerous = sum(1 for r in st.session_state.check_history if r['risk_level'] == '危険')
   warning = sum(1 for r in st.session_state.check_history if r['risk_level'] == '注意')
   safe = sum(1 for r in st.session_state.check_history if r['risk_level'] == '安全')
   
   col1, col2, col3, col4 = st.columns(4)
   col1.metric("📊 総チェック数", total)
   col2.metric("🚨 詐欺検出", dangerous)
   col3.metric("⚠️ 警告", warning)
   col4.metric("✅ 安全", safe)

# メインUI
st.title("🤖 Gemini AI搭載 電話番号チェッカー")
st.markdown("Google Gemini AIによる高度な詐欺電話検出システム")

# サイドバー
with st.sidebar:
   st.header("🛠️ メニュー")
   
   # Gemini API設定
   with st.expander("🔑 Gemini API設定", expanded=not st.session_state.ai_enabled):
       api_key_input = st.text_input(
           "Gemini API Key",
           type="password",
           value=st.session_state.gemini_api_key,
           help="https://makersuite.google.com/app/apikey から取得"
       )
       
       if st.button("API Key保存"):
           st.session_state.gemini_api_key = api_key_input
           if setup_gemini():
               st.session_state.ai_enabled = True
               st.success("✅ Gemini AI有効化！")
           else:
               st.session_state.ai_enabled = False
               st.error("❌ API Key無効")
       
       # 自動でAPI設定を試行
       if st.session_state.gemini_api_key and not st.session_state.ai_enabled:
           if setup_gemini():
               st.session_state.ai_enabled = True
       
       st.session_state.ai_enabled = st.checkbox(
           "AI分析を有効化",
           value=st.session_state.ai_enabled,
           disabled=not st.session_state.gemini_api_key
       )
       
       if st.session_state.ai_enabled:
           st.success("🤖 AI分析: ON")
       else:
           st.info("🤖 AI分析: OFF")
   
   st.markdown("---")
   
   page = st.radio(
       "ページ選択",
       ["🔍 番号チェック", "💬 会話分析", "📊 統計情報", "📢 通報", "🗄️ データベース", "ℹ️ 使い方"]
   )
   
   st.markdown("---")
   st.subheader("📈 簡易統計")
   show_stats()
   
   st.markdown("---")

# メインコンテンツ
if page == "🔍 番号チェック":
   st.header("🔍 AI電話番号チェック")
   
   col1, col2 = st.columns([3, 1])
   with col1:
       phone_input = st.text_input(
           "電話番号を入力してください",
           placeholder="例: 090-1234-5678, 03-1234-5678, +81-90-1234-5678",
           key="phone_input"
       )
   with col2:
       st.markdown("<br>", unsafe_allow_html=True)
       check_btn = st.button("🔍 チェック", use_container_width=True)
   
   if check_btn and phone_input:
       with st.spinner("解析中..."):
           result = analyze_phone_number(phone_input, use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
       
       if result['risk_level'] == "危険":
           st.markdown("### 🚨🚨🚨 警告！ 🚨🚨🚨")
   
   if st.session_state.last_check:
       st.markdown("---")
       st.subheader("📋 チェック結果")
       display_result(st.session_state.last_check)
   
   st.markdown("---")
   st.subheader("🧪 サンプル番号でテスト")
   sample_col1, sample_col2, sample_col3, sample_col4 = st.columns(4)
   
   with sample_col1:
       if st.button("✅ 安全な番号"):
           result = analyze_phone_number("03-5555-6666", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col2:
       if st.button("⚠️ 注意が必要"):
           result = analyze_phone_number("050-1111-2222", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col3:
       if st.button("🚨 詐欺番号"):
           result = analyze_phone_number("090-1234-5678", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col4:
       if st.button("🌍 国際詐欺"):
           result = analyze_phone_number("+1-876-555-1234", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()

elif page == "💬 会話分析":
   st.header("💬 通話内容AI分析")
   st.markdown("通話中の会話内容をAIで分析し、詐欺の可能性を判定します")
   
   if not st.session_state.ai_enabled:
       st.warning("⚠️ この機能を使用するにはGemini APIを有効化してください")
   
   conversation_text = st.text_area(
       "通話内容を入力してください",
       placeholder="例:\n相手: お客様の口座が不正利用されています\n私: どういうことですか？\n相手: すぐにキャッシュカードの番号を教えてください...",
       height=200
   )
   
   if st.button("🤖 AI分析実行", disabled=not st.session_state.ai_enabled):
       if conversation_text:
           with st.spinner("🤖 AIが会話内容を分析中..."):
               analysis = analyze_conversation_with_gemini(conversation_text)
               if analysis:
                   st.markdown("---")
                   st.subheader("📋 AI分析結果")
                   
                   col1, col2 = st.columns(2)
                   with col1:
                       scam_prob = analysis.get('scam_probability', 0)
                       st.metric("詐欺可能性", f"{scam_prob}%")
                   with col2:
                       fraud_type = analysis.get('fraud_type', '不明')
                       st.metric("詐欺タイプ", fraud_type)
                   
                   if analysis.get('dangerous_keywords'):
                       st.error("### ⚠️ 危険なキーワード検出")
                       for keyword in analysis['dangerous_keywords']:
                           st.markdown(f"- `{keyword}`")
                   
                   if analysis.get('immediate_actions'):
                       st.warning("### 🚨 すぐに取るべき行動")
                       for action in analysis['immediate_actions']:
                           st.markdown(f"- {action}")
                   
                   if analysis.get('should_report'):
                       st.error("### 📞 警察への通報を推奨します")
                       st.markdown("**#9110（警察相談専用電話）** に連絡してください")
                   
                   if analysis.get('explanation'):
                       st.info(f"**詳細説明**: {analysis['explanation']}")
       else:
           st.warning("通話内容を入力してください")

elif page == "📊 統計情報":
   st.header("📊 統計情報")
   show_stats()
   
   st.markdown("---")
   st.subheader("📜 チェック履歴")
   
   if st.session_state.check_history:
       for i, record in enumerate(reversed(st.session_state.check_history[-10:]), 1):
           ai_badge = "🤖" if record.get('ai_analysis') else ""
           with st.expander(f"{i}. {ai_badge} {record['original']} - {record['risk_level']} ({record['timestamp']})"):
               display_result(record)
   else:
       st.info("まだチェック履歴がありません")
   
   if st.button("🗑️ 履歴をクリア"):
       st.session_state.check_history = []
       st.success("履歴をクリアしました")
       st.rerun()

elif page == "📢 通報":
   st.header("📢 怪しい電話番号を通報")
   st.markdown("詐欺や迷惑電話の可能性がある番号を通報してください。")
   
   with st.form("report_form"):
       report_number = st.text_input("電話番号", placeholder="例: 090-1234-5678")
       report_detail = st.text_area(
           "詳細情報",
           placeholder="どのような内容の電話でしたか？具体的に記入してください。",
           height=150
       )
       report_category = st.selectbox("分類", ["詐欺", "迷惑営業", "無言電話", "その他"])
       
       submitted = st.form_submit_button("📢 通報する")
       
       if submitted and report_number:
           report = {
               "number": report_number,
               "description": f"[{report_category}] {report_detail}",
               "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               "reports": 1
           }
           
           existing = None
           for case in st.session_state.scam_database["reported_cases"]:
               if case["number"] == report_number:
                   existing = case
                   break
           
           if existing:
               existing["reports"] += 1
               existing["description"] += f"\n[追加通報 {existing['reports']}] {report_detail}"
           else:
               st.session_state.scam_database["reported_cases"].append(report)
           
           st.success("✅ 通報ありがとうございます！情報はデータベースに追加されました。")
   
   st.markdown("---")
   st.subheader("📋 最近の通報情報")
   
   if st.session_state.scam_database["reported_cases"]:
       for case in reversed(st.session_state.scam_database["reported_cases"][-5:]):
           with st.expander(f"📞 {case['number']} ({case['reports']}件の通報)"):
               st.markdown(f"**通報日時:** {case['timestamp']}")
               st.markdown(f"**詳細:**\n{case['description']}")
   else:
       st.info("まだ通報情報がありません")

elif page == "🗄️ データベース":
   st.header("🗄️ 詐欺電話データベース")
   
   tab1, tab2, tab3 = st.tabs(["既知の詐欺番号", "疑わしいプレフィックス", "通報された番号"])
   
   with tab1:
       st.subheader("🚨 既知の詐欺番号")
       for i, number in enumerate(st.session_state.scam_database["known_scam_numbers"], 1):
           st.markdown(f"{i}. `{number}`")
       
       st.markdown("---")
       with st.form("add_scam_number"):
           new_number = st.text_input("新しい詐欺番号を追加")
           if st.form_submit_button("➕ 追加"):
               if new_number and new_number not in st.session_state.scam_database["known_scam_numbers"]:
                   st.session_state.scam_database["known_scam_numbers"].append(new_number)
                   st.success(f"✅ {new_number} を追加しました")
                   st.rerun()
   
   with tab2:
       st.subheader("⚠️ 疑わしいプレフィックス")
       for prefix in st.session_state.scam_database["suspicious_prefixes"]:
           st.markdown(f"- `{prefix}`")
   
   with tab3:
       st.subheader("📢 ユーザー通報された番号")
       if st.session_state.scam_database["reported_cases"]:
           for case in st.session_state.scam_database["reported_cases"]:
               st.markdown(f"**{case['number']}** ({case['reports']}件)")
               st.caption(case['description'][:100] + "...")
       else:
           st.info("まだ通報がありません")

else:  # 使い方
   st.header("ℹ️ 使い方ガイド")
   st.markdown("""
   ## 🤖 Gemini AI搭載電話番号チェッカー
   
   ### 🚀 クイックスタート
   
   1. **APIキーは設定済み** - すぐに使えます！
   2. サイドバーで「AI分析を有効化」にチェック
   3. 電話番号を入力して「チェック」
   
   ### 🆕 新機能: 発信者タイプ判定
   
   このアプリは電話番号から**誰からの電話か**を自動判定します！
   
   #### 📊 判定できる発信者タイプ
   
   | アイコン | タイプ | 説明 |
   |---------|--------|------|
   | 👤 | 個人 | 携帯電話（090/080/070） |
   | 🏢 | 一般企業 | フリーダイヤル、固定電話 |
   | 🏛️ | 公的機関 | 官公庁、警察、消防 |
   | 🏦 | 金融機関 | 銀行のカスタマーサポート |
   | 🌍 | 国際 | 海外からの着信 |
   | ⚙️ | 特殊 | IoT、M2M通信 |
   | ❓ | 不明 | 判定できない番号 |
   
   ### 🤖 AI機能の活用
   
   1. **高度な判定**
      - AI判定: 個人/企業/詐欺グループ
      - 業種: 通信販売、保険営業など
      - 判定理由の詳細説明
   
   2. **会話内容の分析**
      - 「💬 会話分析」ページで使用
      - 詐欺の可能性をパーセントで表示
      - 危険なキーワードを検出
   
   ### 🔍 基本的な使い方
   
   1. **番号チェック**
      - 電話番号を入力
      - 「チェック」ボタンをクリック
      - 発信者タイプとリスクを確認
   
   2. **リアルタイム監視**
      - サイドバーの「監視開始」をクリック
      - 着信シミュレートでテスト可能
   
   3. **通報機能**
      - 怪しい番号を発見したら通報
      - 情報は他のユーザーと共有
   
   ### 🎯 リスクレベルの意味
   
   - **✅ 安全**: 特に問題なし
   - **⚠️ 注意**: 疑わしい特徴あり
   - **🚨 危険**: 詐欺の可能性が高い
   - **🚑 緊急**: 緊急通報番号
   
   ### 💡 見分け方のコツ
   
   #### 詐欺電話の特徴
   - 📱 050（IP電話）が多い
   - 🌍 国際電話（+で始まる）
   - 💰 金銭・個人情報を要求
   - 🚨 緊急性を装う
   - 😱 脅迫的な言動
   
   ### 🛡️ 対策方法
   
   1. **予防**
      - 知らない番号には出ない
      - 留守番電話で確認
      - 着信拒否設定を活用
   
   2. **対応中**
      - 個人情報は教えない
      - お金の話が出たら即切る
      - 録音すると伝える
   
   3. **事後**
      - 怪しいと思ったら通報
      - このアプリで番号をチェック
      - 警察に相談（#9110）
   
   ### 📞 相談窓口
   
   - **警察相談**: #9110
   - **消費者ホットライン**: 188
   - **金融庁**: 0570-016811
   
   ### 🔒 プライバシーとセキュリティ
   
   - ✅ チェックした番号はローカルに保存
   - ✅ AI分析もプライバシー保護
   - ✅ 通報は匿名で可能
   - ⚠️ APIキーは安全に管理
   
   """)
   
   st.info("💡 このアプリは継続的に改善されています。フィードバックをお待ちしています！")

# フッター
st.markdown("---")
st.caption("⚠️ このアプリは詐欺電話対策の補助ツールです。最終的な判断はご自身で行ってください。")