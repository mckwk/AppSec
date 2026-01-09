"""
File Upload Handler
Provides secure file upload functionality with image validation and hardening.
"""
import os
import uuid
import logging
from io import BytesIO
from PIL import Image
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_MIME_TYPES = {
    'image/png': 'png',
    'image/jpeg': 'jpg', 
    'image/gif': 'gif',
    'image/webp': 'webp'
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_IMAGE_DIMENSION = 4096  # Max width/height in pixels

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_safe_filename(original_filename):
    """
    Generate a safe, unique filename.
    
    Args:
        original_filename: Original filename from upload
    
    Returns:
        Safe filename with UUID prefix
    """
    # Get safe version of original name
    safe_name = secure_filename(original_filename)
    
    # Extract extension
    if '.' in safe_name:
        ext = safe_name.rsplit('.', 1)[1].lower()
    else:
        ext = 'jpg'  # Default extension
    
    # Generate unique filename
    unique_id = uuid.uuid4().hex[:16]
    return f"{unique_id}.{ext}"


def validate_image_content(file_stream):
    """
    Validate that file content is actually an image.
    
    Args:
        file_stream: File stream to validate
    
    Returns:
        Tuple (is_valid: bool, detected_format: str or None, error: str or None)
    """
    try:
        file_stream.seek(0)
        img = Image.open(file_stream)
        img.verify()  # Verify it's a valid image
        
        # Check format
        format_lower = img.format.lower() if img.format else None
        if format_lower not in ['png', 'jpeg', 'gif', 'webp']:
            return False, None, f"Unsupported image format: {img.format}"
        
        # Reset stream position
        file_stream.seek(0)
        
        return True, format_lower, None
        
    except Exception as e:
        logging.warning(f"Image validation failed: {e}")
        return False, None, "Invalid or corrupted image file"


def reencode_image(file_stream, output_format='JPEG', max_dimension=MAX_IMAGE_DIMENSION):
    """
    Re-encode image to strip metadata and potential malware.
    This creates a clean copy of the image without any embedded data.
    
    Args:
        file_stream: Input file stream
        output_format: Output format (JPEG, PNG, WEBP)
        max_dimension: Maximum width/height
    
    Returns:
        Tuple (success: bool, output_stream: BytesIO or None, error: str or None)
    """
    try:
        file_stream.seek(0)
        
        # Open image
        img = Image.open(file_stream)
        
        # Convert to RGB if necessary (for JPEG output)
        if output_format.upper() == 'JPEG' and img.mode in ('RGBA', 'P'):
            # Create white background for transparency
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[3] if len(img.split()) > 3 else None)
            img = background
        elif output_format.upper() == 'JPEG' and img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Resize if too large
        if img.width > max_dimension or img.height > max_dimension:
            img.thumbnail((max_dimension, max_dimension), Image.Resampling.LANCZOS)
            logging.info(f"Image resized to {img.size}")
        
        # Create clean copy without metadata
        output = BytesIO()
        
        # Save with minimal metadata
        save_kwargs = {'optimize': True}
        if output_format.upper() == 'JPEG':
            save_kwargs['quality'] = 85
            save_kwargs['progressive'] = True
        elif output_format.upper() == 'PNG':
            save_kwargs['compress_level'] = 6
        elif output_format.upper() == 'WEBP':
            save_kwargs['quality'] = 85
        
        img.save(output, format=output_format.upper(), **save_kwargs)
        output.seek(0)
        
        logging.info(f"Image re-encoded successfully as {output_format}")
        return True, output, None
        
    except Exception as e:
        logging.error(f"Image re-encoding failed: {e}")
        return False, None, f"Failed to process image: {str(e)}"


def validate_file_size(file_stream, max_size=MAX_FILE_SIZE):
    """
    Validate file size.
    
    Args:
        file_stream: File stream to check
        max_size: Maximum allowed size in bytes
    
    Returns:
        Tuple (is_valid: bool, size: int, error: str or None)
    """
    file_stream.seek(0, 2)  # Seek to end
    size = file_stream.tell()
    file_stream.seek(0)  # Reset to beginning
    
    if size > max_size:
        max_mb = max_size / (1024 * 1024)
        size_mb = size / (1024 * 1024)
        return False, size, f"File too large ({size_mb:.1f}MB). Maximum size is {max_mb:.1f}MB"
    
    if size == 0:
        return False, size, "File is empty"
    
    return True, size, None


def validate_and_save_image(file, subfolder='posts'):
    """
    Complete validation and save process for uploaded image.
    
    Args:
        file: werkzeug FileStorage object
        subfolder: Subfolder within uploads directory
    
    Returns:
        Tuple (success: bool, filename or error: str, relative_path: str or None)
    """
    if not file or not file.filename:
        return False, "No file provided", None
    
    # Check filename extension
    if not allowed_file(file.filename):
        return False, "File type not allowed. Allowed types: PNG, JPG, JPEG, GIF, WEBP", None
    
    # Read file into memory for processing
    file_stream = BytesIO(file.read())
    
    # Validate file size
    is_valid, size, error = validate_file_size(file_stream)
    if not is_valid:
        return False, error, None
    
    # Validate image content
    is_valid, detected_format, error = validate_image_content(file_stream)
    if not is_valid:
        return False, error, None
    
    # Determine output format (use original format if supported, otherwise JPEG)
    if detected_format in ['jpeg', 'jpg']:
        output_format = 'JPEG'
        ext = 'jpg'
    elif detected_format == 'png':
        output_format = 'PNG'
        ext = 'png'
    elif detected_format == 'gif':
        output_format = 'GIF'
        ext = 'gif'
    elif detected_format == 'webp':
        output_format = 'WEBP'
        ext = 'webp'
    else:
        output_format = 'JPEG'
        ext = 'jpg'
    
    # Re-encode image (strips metadata, prevents image-based attacks)
    success, clean_stream, error = reencode_image(file_stream, output_format)
    if not success:
        return False, error, None
    
    # Generate safe filename
    unique_id = uuid.uuid4().hex[:16]
    safe_filename = f"{unique_id}.{ext}"
    
    # Create subfolder if needed
    upload_subfolder = os.path.join(UPLOAD_FOLDER, subfolder)
    os.makedirs(upload_subfolder, exist_ok=True)
    
    # Save file
    file_path = os.path.join(upload_subfolder, safe_filename)
    
    try:
        with open(file_path, 'wb') as f:
            f.write(clean_stream.read())
        
        relative_path = f"{subfolder}/{safe_filename}"
        logging.info(f"Image saved successfully: {relative_path}")
        
        return True, safe_filename, relative_path
        
    except Exception as e:
        logging.error(f"Failed to save image: {e}")
        return False, f"Failed to save file: {str(e)}", None


def delete_upload(relative_path):
    """
    Delete an uploaded file.
    
    Args:
        relative_path: Relative path from uploads folder
    
    Returns:
        bool: True if deleted successfully
    """
    if not relative_path:
        return True
    
    file_path = os.path.join(UPLOAD_FOLDER, relative_path)
    
    # Security check - ensure path is within upload folder
    real_path = os.path.realpath(file_path)
    real_upload = os.path.realpath(UPLOAD_FOLDER)
    
    if not real_path.startswith(real_upload):
        logging.warning(f"Attempted path traversal in delete_upload: {relative_path}")
        return False
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"Deleted upload: {relative_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to delete upload {relative_path}: {e}")
        return False


def get_upload_path(relative_path):
    """
    Get full filesystem path for an upload.
    
    Args:
        relative_path: Relative path from uploads folder
    
    Returns:
        str or None: Full path if valid and exists
    """
    if not relative_path:
        return None
    
    file_path = os.path.join(UPLOAD_FOLDER, relative_path)
    
    # Security check - ensure path is within upload folder
    real_path = os.path.realpath(file_path)
    real_upload = os.path.realpath(UPLOAD_FOLDER)
    
    if not real_path.startswith(real_upload):
        logging.warning(f"Attempted path traversal in get_upload_path: {relative_path}")
        return None
    
    if os.path.exists(file_path):
        return file_path
    
    return None
