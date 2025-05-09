from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from moviepy.editor import VideoFileClip
import imageio
import re
from abc import ABC, abstractmethod

# Regular Expression Patterns
class RegexPatterns:
    """Class containing all regular expression patterns"""
    # Video filename pattern: more flexible pattern for video files
    VIDEO_FILENAME = r'^[\w\s\-\.]+\.(mp4|avi|mov|wmv|flv|mkv|MP4|AVI|MOV|WMV|FLV|MKV)$'
    
    # Username pattern: 3-20 characters, alphanumeric, underscore, hyphen
    USERNAME = r'^[a-zA-Z0-9_\-]{3,20}$'
    
    # Password pattern: at least 8 characters, must contain uppercase, lowercase, number, and special character
    PASSWORD = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    
    # Video title pattern: 2-100 characters, alphanumeric, spaces, and common punctuation
    VIDEO_TITLE = r'^[a-zA-Z0-9\s\.,!?\-_]{2,100}$'
    
    # Resolution pattern: standard video resolutions
    RESOLUTION = r'^(480p|720p|1080p|4K)$'
    
    # Duration pattern: HH:MM:SS format
    DURATION = r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$'
    
    # File size pattern: number followed by B, KB, MB, GB
    FILE_SIZE = r'^\d+(\.\d+)?\s*(B|KB|MB|GB)$'

# Base Exception Classes
class VideoStreamingError(Exception):
    """Base exception class for video streaming application"""
    pass

class VideoUploadError(VideoStreamingError):
    """Exception raised for video upload related errors"""
    pass

class ThumbnailGenerationError(VideoStreamingError):
    """Exception raised for thumbnail generation errors"""
    pass

class AuthenticationError(VideoStreamingError):
    """Exception raised for authentication related errors"""
    pass

# 1. Encapsulation
class MediaFile:
    """Base class demonstrating encapsulation"""
    def __init__(self, filename, size):
        # More permissive filename validation
        if not self.is_valid_filename(filename):
            # Attempt to sanitize the filename
            safe_filename = self.sanitize_filename(filename)
            if not self.is_valid_filename(safe_filename):
                raise ValueError("Invalid filename format")
            filename = safe_filename
        self._filename = filename
        self.__size = size
        self._upload_date = datetime.utcnow()
    
    # Getter methods
    def get_filename(self):
        return self._filename
    
    def get_size(self):
        return self.__size
    
    def get_upload_date(self):
        return self._upload_date
    
    # Setter methods with validation
    def set_filename(self, filename):
        if not self.is_valid_filename(filename):
            safe_filename = self.sanitize_filename(filename)
            if not self.is_valid_filename(safe_filename):
                raise ValueError("Invalid filename format")
            filename = safe_filename
        self._filename = filename
    
    def set_size(self, size):
        if isinstance(size, str):
            if not re.match(RegexPatterns.FILE_SIZE, size):
                raise ValueError("Invalid file size format")
        elif size < 0:
            raise ValueError("Size cannot be negative")
        self.__size = size
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to make it valid"""
        # Remove any path components
        filename = os.path.basename(filename)
        
        # Replace invalid characters with underscore
        safe_name = re.sub(r'[^\w\-\. ]', '_', filename)
        
        # Ensure filename is not empty and has valid extension
        if not safe_name or '.' not in safe_name:
            return None
            
        name, ext = safe_name.rsplit('.', 1)
        if not name:
            return None
            
        # Return sanitized filename
        return f"{name}.{ext.lower()}"
    
    @staticmethod
    def is_valid_filename(filename):
        """Validate filename format using more permissive regex"""
        if not filename or '.' not in filename:
            return False
            
        name, ext = filename.rsplit('.', 1)
        if not name:
            return False
            
        # Check if extension is valid (case insensitive)
        valid_extensions = {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'}
        if ext.lower() not in valid_extensions:
            return False
            
        # More permissive filename validation
        return bool(re.match(r'^[\w\-\. ]+\.[a-zA-Z0-9]+$', filename))

# 2. Inheritance and Polymorphism
class Video(MediaFile):
    """Video class demonstrating inheritance and polymorphism"""
    def __init__(self, filename, size, duration=0, resolution="1080p"):
        # Call parent class constructor without named arguments
        super().__init__(filename, size)
        if not re.match(RegexPatterns.RESOLUTION, resolution):
            raise ValueError("Invalid resolution format")
        if duration < 0:
            raise ValueError("Duration cannot be negative")
        self.duration = duration
        self.resolution = resolution
    
    def get_info(self):
        return f"Video: {self._filename}, Duration: {self.format_duration(self.duration)}, Resolution: {self.resolution}"
    
    @staticmethod
    def get_supported_resolutions():
        """Get list of supported video resolutions"""
        return ['480p', '720p', '1080p', '4K']
    
    @staticmethod
    def format_duration(seconds):
        """Convert seconds to HH:MM:SS format"""
        if not isinstance(seconds, (int, float)):
            return "00:00:00"
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

# 3. Abstraction
class MediaProcessor(ABC):
    """Abstract base class for media processing"""
    @abstractmethod
    def process(self, file):
        pass
    
    @abstractmethod
    def validate(self, file):
        pass
    
    @staticmethod
    def get_supported_formats():
        """Get all supported media formats"""
        return {
            'video': ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'],
            'audio': ['mp3', 'wav', 'ogg', 'aac', 'flac']
        }

class VideoProcessor(MediaProcessor):
    """Concrete implementation for video processing"""
    def process(self, file):
        if not isinstance(file, Video):
            raise TypeError("Expected Video object")
        print(f"Processing video: {file.get_filename()}")
        return True
    
    def validate(self, file):
        if not isinstance(file, Video):
            raise TypeError("Expected Video object")
        return (file.duration > 0 and 
                re.match(RegexPatterns.RESOLUTION, file.resolution) and 
                re.match(RegexPatterns.VIDEO_FILENAME, file.get_filename()))

class EnhancedVideoProcessor(VideoProcessor):
    """Enhanced video processor with additional features"""
    def process(self, file):
        super().process(file)
        print(f"Additional processing for {file.get_filename()}")
        return True
    
    def validate(self, file):
        if not super().validate(file):
            return False
        return file.resolution in ['720p', '1080p', '4K']

class VideoService(MediaProcessor):
    """Service class for video-related operations"""
    def __init__(self, app):
        self.app = app
        self.upload_folder = app.config['UPLOAD_FOLDER']
        self.thumbnail_folder = app.config['THUMBNAIL_FOLDER']
        self.allowed_extensions = {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'}
        self.processor = EnhancedVideoProcessor()
        # Ensure folders exist
        os.makedirs(self.upload_folder, exist_ok=True)
        os.makedirs(self.thumbnail_folder, exist_ok=True)
    
    def process(self, file):
        """Process video file"""
        if not isinstance(file, Video):
            raise TypeError("Expected Video object")
        return self.processor.process(file)
    
    def validate(self, file):
        """Validate video file"""
        if not isinstance(file, Video):
            raise TypeError("Expected Video object")
        return self.processor.validate(file)
    
    def generate_thumbnail(self, video_path, thumbnail_path):
        """Generate thumbnail from video file"""
        try:
            if not os.path.exists(video_path):
                raise ThumbnailGenerationError("Video file not found")
            
            try:
                # Try using VideoFileClip first
                video = VideoFileClip(video_path)
                time = min(1, video.duration)
                video.save_frame(thumbnail_path, t=time)
                video.close()
                print(f"Thumbnail generated using VideoFileClip: {thumbnail_path}")
                return True
            except Exception as e:
                print(f"VideoFileClip failed: {e}")
                # Fallback to imageio if VideoFileClip fails
                reader = imageio.get_reader(video_path)
                first_frame = reader.get_data(0)
                imageio.imwrite(thumbnail_path, first_frame)
                reader.close()
                print(f"Thumbnail generated using imageio: {thumbnail_path}")
                return True
        except Exception as e:
            print(f"Thumbnail generation failed: {e}")
            raise ThumbnailGenerationError(f"Failed to generate thumbnail: {str(e)}")
    
    def save_video(self, video_file, title):
        """Save uploaded video and generate thumbnail"""
        video_path = None
        try:
            if not video_file or not hasattr(video_file, 'filename') or video_file.filename == '':
                raise VideoUploadError("No video file selected")
            
            # Print debug information
            print(f"Uploading file: {video_file.filename}")
            print(f"Content Type: {video_file.content_type}")
            print(f"File Size: {video_file.content_length}")
            
            # Sanitize and validate filename
            original_filename = video_file.filename
            safe_filename = MediaFile.sanitize_filename(original_filename)
            
            if not safe_filename:
                raise VideoUploadError(f"Invalid filename: {original_filename}")
            
            # Check file extension
            ext = safe_filename.rsplit('.', 1)[1].lower()
            if ext not in self.allowed_extensions:
                raise VideoUploadError(f"Invalid video format. Allowed formats: {', '.join(self.allowed_extensions)}")
            
            # Validate title
            if not title or not re.match(RegexPatterns.VIDEO_TITLE, title):
                raise VideoUploadError("Invalid video title format")
            
            # Generate unique filename with timestamp
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{timestamp}_{safe_filename}"
            video_path = os.path.join(self.upload_folder, unique_filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(video_path), exist_ok=True)
            
            # Save the file
            try:
                video_file.save(video_path)
                print(f"File saved to: {video_path}")
            except Exception as e:
                raise VideoUploadError(f"Failed to save video file: {str(e)}")
            
            if not os.path.exists(video_path):
                raise VideoUploadError("File was not saved successfully")
            
            # Generate thumbnail
            thumbnail_filename = f"thumb_{unique_filename.rsplit('.', 1)[0]}.jpg"
            thumbnail_path = os.path.join(self.thumbnail_folder, thumbnail_filename)
            
            # Ensure thumbnail directory exists
            os.makedirs(os.path.dirname(thumbnail_path), exist_ok=True)
            
            if self.generate_thumbnail(video_path, thumbnail_path):
                return unique_filename, thumbnail_filename
            raise ThumbnailGenerationError("Failed to generate thumbnail")
            
        except Exception as e:
            # Clean up if something goes wrong and video_path exists
            if video_path and os.path.exists(video_path):
                try:
                    os.remove(video_path)
                except Exception as cleanup_error:
                    print(f"Error during cleanup: {cleanup_error}")
            raise VideoUploadError(f"Failed to upload video: {str(e)}")
    
    @staticmethod
    def _is_allowed_file(filename, allowed_extensions=None):
        """Check if file extension is allowed"""
        if allowed_extensions is None:
            allowed_extensions = {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv',
                                'MP4', 'AVI', 'MOV', 'WMV', 'FLV', 'MKV'}
        
        if '.' not in filename:
            return False
            
        extension = filename.rsplit('.', 1)[1].lower()
        return extension in allowed_extensions

class UserService:
    """Service class for user-related operations"""
    def __init__(self, db):
        self.db = db
    
    def create_user(self, username, password):
        """Create a new user with validation"""
        try:
            # Validate username format
            if not User.validate_username(username):
                raise AuthenticationError("Invalid username format. Must be 3-20 characters, alphanumeric, underscore, or hyphen")
            
            # Validate password strength
            if not User.validate_password(password):
                raise AuthenticationError("Password must be at least 8 characters and contain uppercase, lowercase, number, and special character")
            
            # Check if username exists
            if User.query.filter_by(username=username).first():
                raise AuthenticationError("Username already exists")
            
            # Create new user
            user = User(
                username=username,
                password_hash=generate_password_hash(password)
            )
            self.db.session.add(user)
            self.db.session.commit()
            return user
        except Exception as e:
            self.db.session.rollback()
            raise AuthenticationError(f"Failed to create user: {str(e)}")
    
    def authenticate_user(self, username, password):
        """Authenticate user with validation"""
        try:
            # Validate username format
            if not User.validate_username(username):
                raise AuthenticationError("Invalid username format")
            
            # Get user from database
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                raise AuthenticationError("Invalid username or password")
            return user
        except Exception as e:
            raise AuthenticationError(f"Authentication failed: {str(e)}")

# Flask Application Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = '2404118'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///video_streaming.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['THUMBNAIL_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'thumbnails')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize services
video_service = VideoService(app)
user_service = UserService(db)

# Ensure upload folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_superuser = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def validate_username(username):
        """Validate username format using regex"""
        return bool(re.match(RegexPatterns.USERNAME, username))
    
    @staticmethod
    def validate_password(password):
        """Validate password strength using regex"""
        return bool(re.match(RegexPatterns.PASSWORD, password))

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    thumbnail_filename = db.Column(db.String(255))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def validate_title(title):
        """Validate video title format using regex"""
        return bool(re.match(RegexPatterns.VIDEO_TITLE, title))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(VideoStreamingError)
def handle_video_streaming_error(error):
    """Handle custom exceptions"""
    flash(str(error))
    return redirect(request.referrer or url_for('home'))

@app.route('/')
@login_required
def home():
    try:
        search_query = request.args.get('search', '')
        if search_query:
            videos = Video.query.filter(Video.title.ilike(f'%{search_query}%')).order_by(Video.upload_date.desc()).all()
        else:
            videos = Video.query.order_by(Video.upload_date.desc()).all()
        return render_template('home.html', videos=videos, search_query=search_query)
    except Exception as e:
        flash(f"Error loading videos: {str(e)}")
        return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            user = user_service.create_user(username, password)
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except AuthenticationError as e:
            flash(str(e))
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            user = user_service.authenticate_user(username, password)
            login_user(user)
            return redirect(url_for('home'))
        except AuthenticationError as e:
            flash(str(e))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not current_user.is_superuser:
        flash('Only superusers can upload videos')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Check if the post request has the video file part
            if 'video' not in request.files:
                flash('No video file selected')
                return redirect(request.url)
            
            video = request.files['video']
            title = request.form.get('title', '').strip()
            
            # Check if a file was actually selected
            if video.filename == '':
                flash('No video file selected')
                return redirect(request.url)
            
            # Check if title was provided
            if not title:
                flash('Please provide a title for the video')
                return redirect(request.url)
            
            # Ensure upload folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)
            
            try:
                filename, thumbnail_filename = video_service.save_video(video, title)
                
                # Create new video entry in database
                new_video = Video(
                    title=title,
                    filename=filename,
                    thumbnail_filename=thumbnail_filename
                )
                db.session.add(new_video)
                db.session.commit()
                
                flash('Video uploaded successfully!')
                return redirect(url_for('home'))
                
            except VideoUploadError as e:
                flash(str(e))
                return redirect(request.url)
                
        except Exception as e:
            flash(f'An unexpected error occurred: {str(e)}')
            return redirect(request.url)
    
    # GET request - show upload form
    return render_template('upload.html')

@app.route('/delete_video/<int:video_id>')
@login_required
def delete_video(video_id):
    if not current_user.is_superuser:
        flash('Only superusers can delete videos')
        return redirect(url_for('home'))
    
    try:
        video = Video.query.get_or_404(video_id)
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.filename)
        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], video.thumbnail_filename)
        
        if os.path.exists(video_path):
            os.remove(video_path)
        if os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)
            
        db.session.delete(video)
        db.session.commit()
        flash('Video deleted successfully!')
    except Exception as e:
        flash(f'Error deleting video: {str(e)}')
    
    return redirect(url_for('home'))

@app.route('/video/<int:video_id>')
@login_required
def watch_video(video_id):
    video = Video.query.get_or_404(video_id)
    return render_template('watch.html', video=video)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_superuser:
        flash('Access denied. Only superusers can access the admin dashboard.')
        return redirect(url_for('home'))
    
    users = User.query.all()
    videos = Video.query.order_by(Video.upload_date.desc()).all()
    return render_template('admin_dashboard.html', users=users, videos=videos)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_superuser:
        flash('Access denied. Only superusers can delete users.')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    if user.is_superuser:
        flash('Cannot delete superuser accounts.')
        return redirect(url_for('admin_dashboard'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!')
    except Exception as e:
        flash('Error deleting user')
    
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            
            if not User.query.filter_by(username='piyu').first():
                superuser = User(
                    username='piyu',
                    password_hash=generate_password_hash('piyu'),
                    is_superuser=True
                )
                db.session.add(superuser)
                db.session.commit()
                print("Superuser created successfully!")
            else:
                print("Superuser already exists!")
                
            print("Database initialized successfully!")
        except Exception as e:
            print(f"Error initializing database: {e}")
            db.session.rollback()
            
    app.run(debug=True) 