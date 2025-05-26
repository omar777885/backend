const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
// Replace your current CORS middleware with this:
const allowedOrigins = [
  'http://localhost:3000', 
  'https://snazzy-sunflower-a40cb2.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Handle preflight requests
app.options('*', cors());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI )
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  nationalId: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  age: { type: Number },
  bloodType: { type: String },
  profileImage: { type: String, default: '/profile-image.jpg' },
  createdAt: { type: Date, default: Date.now }
});

// Blood Analysis Schema
const bloodAnalysisSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  testNumber: { type: String, required: true, unique: true },
  testName: { type: String, required: true },
  testDate: { type: Date, default: Date.now },
  status: { type: String, default: 'ready', enum: ['pending', 'ready', 'processing'] },
  results: {
    hemoglobin: { type: Number },
    whiteBloodCells: { type: Number },
    redBloodCells: { type: Number },
    platelets: { type: Number },
    glucose: { type: Number },
    cholesterol: { type: Number },
    // Add more test parameters as needed
  },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now }
});

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  testType: { type: String, required: true },
  appointmentDate: { type: Date, required: true },
  appointmentTime: { type: String, required: true },
  branch: { type: String, required: true },
  status: { type: String, default: 'scheduled', enum: ['scheduled', 'completed', 'cancelled'] },
  createdAt: { type: Date, default: Date.now }
});

// Home Visit Schema
const homeVisitSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  testType: { type: String, required: true },
  visitDate: { type: Date, required: true },
  visitTime: { type: String, required: true },
  address: { type: String, required: true },
  phone: { type: String, required: true },
  status: { type: String, default: 'scheduled', enum: ['scheduled', 'completed', 'cancelled'] },
  createdAt: { type: Date, default: Date.now }
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  type: { type: String, required: true, enum: ['test_result', 'appointment', 'general'] },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const BloodAnalysis = mongoose.model('BloodAnalysis', bloodAnalysisSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const HomeVisit = mongoose.model('HomeVisit', homeVisitSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Contact = mongoose.model('Contact', contactSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Auth Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, nationalId, password, confirmPassword } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !phone || !nationalId || !password) {
      return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'كلمتا المرور غير متطابقتان' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { nationalId }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'المستخدم موجود بالفعل بهذا البريد الإلكتروني أو الرقم القومي' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      firstName,
      lastName,
      email,
      phone,
      nationalId,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'تم إنشاء الحساب بنجاح',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'بيانات الدخول غير صحيحة' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        phone: user.phone,
        role: user.role,
        age: user.age,
        bloodType: user.bloodType,
        profileImage: user.profileImage
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// User Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/user/dashboard', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get user's tests
    const recentTests = await BloodAnalysis.find({ userId })
      .sort({ createdAt: -1 })
      .limit(3);

    // Get user's appointments
    const upcomingAppointments = await Appointment.find({ 
      userId, 
      appointmentDate: { $gte: new Date() }
    }).sort({ appointmentDate: 1 }).limit(3);

    // Get user's notifications
    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(5);

    // Get counts
    const testsCount = await BloodAnalysis.countDocuments({ userId });
    const appointmentsCount = await Appointment.countDocuments({ 
      userId, 
      appointmentDate: { $gte: new Date() }
    });
    const reportsCount = await BloodAnalysis.countDocuments({ userId, status: 'ready' });
    const unreadNotifications = await Notification.countDocuments({ userId, isRead: false });

    res.json({
      success: true,
      data: {
        recentTests,
        upcomingAppointments,
        notifications,
        counts: {
          tests: testsCount,
          appointments: appointmentsCount,
          reports: reportsCount,
          notifications: unreadNotifications
        }
      }
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Appointment Routes
app.post('/api/appointments', authenticateToken, async (req, res) => {
  try {
    const { testType, appointmentDate, appointmentTime, branch } = req.body;
    const userId = req.user.userId;

    // Validation
    if (!testType || !appointmentDate || !appointmentTime || !branch) {
      return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    }

    // Check if appointment date is not in the past
    const selectedDate = new Date(appointmentDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (selectedDate < today) {
      return res.status(400).json({ success: false, message: 'لا يمكن حجز موعد في تاريخ سابق' });
    }

    // Create appointment
    const appointment = new Appointment({
      userId,
      testType,
      appointmentDate: selectedDate,
      appointmentTime,
      branch
    });

    await appointment.save();

    // Create notification
    const notification = new Notification({
      userId,
      message: `تم حجز موعدك بنجاح لـ ${testType} في ${appointmentTime} بتاريخ ${selectedDate.toLocaleDateString('ar-EG')}`,
      type: 'appointment'
    });

    await notification.save();

    res.status(201).json({
      success: true,
      message: 'تم حجز الموعد بنجاح',
      appointment
    });

  } catch (error) {
    console.error('Appointment booking error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Get user appointments
app.get('/api/appointments', authenticateToken, async (req, res) => {
  try {
    const appointments = await Appointment.find({ userId: req.user.userId })
      .sort({ appointmentDate: -1 });

    res.json({
      success: true,
      appointments
    });

  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Update appointment
app.put('/api/appointments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { testType, appointmentDate, appointmentTime, branch } = req.body;
    
    const appointment = await Appointment.findOne({ 
      _id: id, 
      userId: req.user.userId 
    });

    if (!appointment) {
      return res.status(404).json({ success: false, message: 'الموعد غير موجود' });
    }

    appointment.testType = testType || appointment.testType;
    appointment.appointmentDate = appointmentDate || appointment.appointmentDate;
    appointment.appointmentTime = appointmentTime || appointment.appointmentTime;
    appointment.branch = branch || appointment.branch;

    await appointment.save();

    res.json({
      success: true,
      message: 'تم تحديث الموعد بنجاح',
      appointment
    });

  } catch (error) {
    console.error('Update appointment error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Cancel appointment
app.delete('/api/appointments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const appointment = await Appointment.findOne({ 
      _id: id, 
      userId: req.user.userId 
    });

    if (!appointment) {
      return res.status(404).json({ success: false, message: 'الموعد غير موجود' });
    }

    appointment.status = 'cancelled';
    await appointment.save();

    res.json({
      success: true,
      message: 'تم إلغاء الموعد بنجاح'
    });

  } catch (error) {
    console.error('Cancel appointment error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Home Visit Routes
app.post('/api/home-visits', authenticateToken, async (req, res) => {
  try {
    const { testType, visitDate, visitTime, address, phone } = req.body;
    const userId = req.user.userId;

    // Validation
    if (!testType || !visitDate || !visitTime || !address || !phone) {
      return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    }

    // Check if visit date is not in the past
    const selectedDate = new Date(visitDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (selectedDate < today) {
      return res.status(400).json({ success: false, message: 'لا يمكن حجز زيارة في تاريخ سابق' });
    }

    // Create home visit
    const homeVisit = new HomeVisit({
      userId,
      testType,
      visitDate: selectedDate,
      visitTime,
      address,
      phone
    });

    await homeVisit.save();

    // Create notification
    const notification = new Notification({
      userId,
      message: `تم حجز الزيارة المنزلية بنجاح لـ ${testType} في ${visitTime} بتاريخ ${selectedDate.toLocaleDateString('ar-EG')}`,
      type: 'appointment'
    });

    await notification.save();

    res.status(201).json({
      success: true,
      message: 'تم حجز الزيارة المنزلية بنجاح',
      homeVisit
    });

  } catch (error) {
    console.error('Home visit booking error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Blood Analysis Routes
app.get('/api/blood-analysis', authenticateToken, async (req, res) => {
  try {
    const tests = await BloodAnalysis.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });

    res.json({ success: true, tests });
  } catch (error) {
    console.error('Blood analysis error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/blood-analysis/:userId', authenticateToken, async (req, res) => {
  try {
    const tests = await BloodAnalysis.find({ userId: req.params.userId })
      .sort({ createdAt: -1 });

    res.json({ success: true, tests });
  } catch (error) {
    console.error('Blood analysis error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

app.get('/api/blood-analysis/result/:testNumber', authenticateToken, async (req, res) => {
  try {
    const test = await BloodAnalysis.findOne({ testNumber: req.params.testNumber })
      .populate('userId', 'firstName lastName email');

    if (!test) {
      return res.status(404).json({ success: false, message: 'التحليل غير موجود' });
    }

    res.json({ success: true, test });
  } catch (error) {
    console.error('Test result error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Notifications Routes
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });

    res.json({ success: true, notifications });
  } catch (error) {
    console.error('Notifications error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!notification) {
      return res.status(404).json({ success: false, message: 'الإشعار غير موجود' });
    }

    notification.isRead = true;
    await notification.save();

    res.json({ success: true, message: 'تم تحديث الإشعار' });
  } catch (error) {
    console.error('Mark notification read error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Contact Route
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ success: false, message: 'جميع الحقول مطلوبة' });
    }

    const contact = new Contact({
      name,
      email,
      phone,
      subject,
      message
    });

    await contact.save();

    res.status(201).json({
      success: true,
      message: 'تم إرسال رسالتك بنجاح. سنتواصل معك قريباً'
    });

  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Admin Routes
app.post('/api/admin/upload-profile', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const admin = await User.findById(req.user.userId);
    if (!admin) {
      return res.status(404).json({ success: false, message: 'المدير غير موجود' });
    }

    // Handle file upload (you'll need to implement file storage logic)
    // For now, we'll just update the profile image URL
    const imageUrl = req.body.imageUrl; // You should implement proper file upload
    admin.profileImage = imageUrl;
    await admin.save();

    res.json({
      success: true,
      message: 'تم تحديث الصورة بنجاح',
      imageUrl: admin.profileImage
    });
  } catch (error) {
    console.error('Profile upload error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Get all users
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const users = await User.find({ role: 'user' }).select('-password');
    res.json({ success: true, users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Update user
app.put('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { userId } = req.params;
    const updates = req.body;

    // Don't allow role updates through this route
    delete updates.role;
    delete updates.password;

    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updates },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Delete user
app.delete('/api/admin/users/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { userId } = req.params;
    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'المستخدم غير موجود' });
    }

    // Delete associated data
    await BloodAnalysis.deleteMany({ userId });
    await Appointment.deleteMany({ userId });
    await HomeVisit.deleteMany({ userId });
    await Notification.deleteMany({ userId });

    res.json({ success: true, message: 'تم حذف المستخدم بنجاح' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Add new test result
app.post('/api/admin/test-results', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { userId, testName, results, notes } = req.body;

    // Generate unique test number
    const testNumber = `TEST-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    const testResult = new BloodAnalysis({
      userId,
      testNumber,
      testName,
      results,
      notes,
      status: 'ready'
    });

    await testResult.save();

    // Create notification for user
    const notification = new Notification({
      userId,
      message: `تم إضافة نتيجة تحليل جديد: ${testName}`,
      type: 'test_result'
    });

    await notification.save();

    res.status(201).json({
      success: true,
      message: 'تم إضافة نتيجة التحليل بنجاح',
      testResult
    });
  } catch (error) {
    console.error('Add test result error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Update test result
app.put('/api/admin/test-results/:testId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { testId } = req.params;
    const updates = req.body;

    const testResult = await BloodAnalysis.findByIdAndUpdate(
      testId,
      { $set: updates },
      { new: true }
    );

    if (!testResult) {
      return res.status(404).json({ success: false, message: 'نتيجة التحليل غير موجودة' });
    }

    // Create notification for user
    const notification = new Notification({
      userId: testResult.userId,
      message: `تم تحديث نتيجة تحليل: ${testResult.testName}`,
      type: 'test_result'
    });

    await notification.save();

    res.json({
      success: true,
      message: 'تم تحديث نتيجة التحليل بنجاح',
      testResult
    });
  } catch (error) {
    console.error('Update test result error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Get admin dashboard stats
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const totalUsers = await User.countDocuments({ role: 'user' });
    const totalTests = await BloodAnalysis.countDocuments();
    const pendingTests = await BloodAnalysis.countDocuments({ status: 'pending' });
    const totalAppointments = await Appointment.countDocuments();
    const totalHomeVisits = await HomeVisit.countDocuments();
    const unreadContacts = await Contact.countDocuments({ isRead: false });

    // Calculate revenue (example calculation)
    const revenue = totalTests * 100; // Assuming each test costs 100

    res.json({
      success: true,
      stats: {
        totalUsers,
        totalTests,
        pendingTests,
        totalAppointments,
        totalHomeVisits,
        unreadContacts,
        revenue
      }
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Get reports
app.get('/api/admin/reports', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { startDate, endDate, type } = req.query;

    let query = {};
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    let report;
    switch (type) {
      case 'tests':
        report = await BloodAnalysis.find(query)
          .populate('userId', 'firstName lastName email')
          .sort({ createdAt: -1 });
        break;
      case 'appointments':
        report = await Appointment.find(query)
          .populate('userId', 'firstName lastName email')
          .sort({ appointmentDate: -1 });
        break;
      case 'home-visits':
        report = await HomeVisit.find(query)
          .populate('userId', 'firstName lastName email')
          .sort({ visitDate: -1 });
        break;
      default:
        return res.status(400).json({ success: false, message: 'نوع التقرير غير صالح' });
    }

    res.json({ success: true, report });
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Update admin settings
app.put('/api/admin/settings', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بهذا الإجراء' });
    }

    const { currentPassword, newPassword } = req.body;

    const admin = await User.findById(req.user.userId);
    if (!admin) {
      return res.status(404).json({ success: false, message: 'المدير غير موجود' });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, admin.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.json({ success: true, message: 'تم تحديث كلمة المرور بنجاح' });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

// Seed some test data
app.post('/api/seed', async (req, res) => {
  try {
    // Create sample blood analysis data for testing
    const users = await User.find({ role: 'user' });
    
    if (users.length > 0) {
      const testData = [
        {
          userId: users[0]._id,
          testNumber: '12345',
          testName: 'تحليل صورة دم كاملة',
          testDate: new Date('2023-04-10'),
          status: 'ready',
          results: {
            hemoglobin: 14.5,
            whiteBloodCells: 7.2,
            redBloodCells: 4.8,
            platelets: 250
          }
        },
        {
          userId: users[0]._id,
          testNumber: '12346',
          testName: 'تحليل وظائف الكبد',
          testDate: new Date('2023-04-05'),
          status: 'ready',
          results: {
            glucose: 95,
            cholesterol: 180
          }
        },
        {
          userId: users[0]._id,
          testNumber: '12347',
          testName: 'تحليل هرمونات الغدة الدرقية',
          testDate: new Date('2023-04-01'),
          status: 'ready'
        }
      ];

      await BloodAnalysis.insertMany(testData);

      // Create sample appointment
      const appointmentData = {
        userId: users[0]._id,
        testType: 'تحليل دم شامل',
        appointmentDate: new Date('2023-04-15'),
        appointmentTime: '10:30 صباحاً',
        branch: 'فرع مدينة نصر',
        status: 'scheduled'
      };

      await Appointment.create(appointmentData);
      

      // Create sample notifications
      const notificationData = [
        {
          userId: users[0]._id,
          message: 'تم الانتهاء من نتائج تحليل صورة الدم الكاملة',
          type: 'test_result'
        },
        {
          userId: users[0]._id,
          message: 'تذكير بموعدك القادم يوم 15 أبريل الساعة 10:30 صباحاً',
          type: 'appointment'
        }
      ];

      await Notification.insertMany(notificationData);
    }

    res.json({ success: true, message: 'Sample data created successfully' });
  } catch (error) {
    console.error('Seed error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ في الخادم' });
  }
});

app.post('/api/create-admin', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    
    const adminData = {
      firstName: "مدير",
      lastName: "المعمل",
      email: "admin@lab.com",
      phone: "01000000000", 
      nationalId: "99999999999999",
      password: hashedPassword,
      role: "admin"
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    res.json({ success: true, message: "Admin created successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});