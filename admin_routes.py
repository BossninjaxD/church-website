from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from models import ContentModel

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/content')
def admin_content():
    content = ContentModel.get_content()
    return render_template('admin_content.html', content=content)

@admin_bp.route('/update_content', methods=['POST'])
def update_content():
    data = request.json
    section_name = data.get("section_name")
    new_content = data.get("content")

    if not section_name or not new_content:
        return jsonify({"success": False, "error": "Invalid data"}), 400

    ContentModel.update_content(section_name, new_content)
    return jsonify({"success": True})
