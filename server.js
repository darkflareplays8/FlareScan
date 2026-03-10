const express = require('express')
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const cors = require('cors')
const { analyze } = require('./peAnalyzer')

const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.static(path.join(__dirname, 'public')))

const upload = multer({
  dest: path.join(__dirname, 'uploads'),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.exe', '.dll', '.msi', '.scr', '.bat', '.com']
    const ext = path.extname(file.originalname).toLowerCase()
    if (allowed.includes(ext)) return cb(null, true)
    cb(new Error('Only EXE, DLL, MSI, SCR, BAT, COM files are supported'))
  }
})

app.post('/api/scan', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' })

  const filePath = req.file.path

  try {
    const result = analyze(filePath)
    res.json(result)
  } catch (err) {
    console.error('Analysis error:', err)
    res.status(500).json({ error: 'Analysis failed: ' + err.message })
  } finally {
    fs.unlink(filePath, () => {})
  }
})

app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large (max 50MB)' })
  res.status(400).json({ error: err.message })
})

app.listen(PORT, () => {
  console.log(`FlareScan running on http://localhost:${PORT}`)
})
