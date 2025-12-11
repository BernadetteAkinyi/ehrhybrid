document.addEventListener("DOMContentLoaded", function() {
  // 🔔 Show Bootstrap Toast
  const toastEl = document.getElementById('toast');
  const toast = new bootstrap.Toast(toastEl);
  toast.show();

  // 🕒 Live Clock
  function updateClock() {
    const clock = document.getElementById('clock');
    const now = new Date();
    clock.textContent = now.toLocaleTimeString();
  }
  setInterval(updateClock, 1000);
  updateClock();

  // ☰ Sidebar Toggle
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('toggleSidebar');
  toggleBtn.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
  });

  // 🎨 Role-Based Theme
  const roleText = document.querySelector('.navbar-text')?.textContent || '';
  if (roleText.includes('Admin')) document.body.classList.add('admin-theme');
  else if (roleText.includes('Doctor')) document.body.classList.add('doctor-theme');
  else if (roleText.includes('Nurse')) document.body.classList.add('nurse-theme');
});