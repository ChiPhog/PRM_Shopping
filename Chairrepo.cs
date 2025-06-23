using FPTMOBILE.Models; // Đảm bảo đã import namespace của Chairs
using System;
using System.Collections.Generic;
using System.Linq; // Để sử dụng các phương thức LINQ như FirstOrDefault, Where, v.v.

namespace FPTMOBILE
{
    public class Chairrepo
    {
        // Đây là nơi lưu trữ dữ liệu tạm thời trong bộ nhớ.
        // Trong ứng dụng thực tế, bạn sẽ thay thế nó bằng kết nối cơ sở dữ liệu.
        private List<Chairs> _chairs = new List<Chairs>();


        // ---------- C (Create) - Thêm mới ghế ----------
        public Chairs AddChair(Chairs chair)
        {
            if (chair == null)
            {
                throw new ArgumentNullException(nameof(chair));
            }

            // Gán một ID mới nếu chưa có (thường thì nên để database tự sinh)
            if (chair.id == Guid.Empty)
            {
                chair.id = Guid.NewGuid();
            }

            _chairs.Add(chair);
            return chair; // Trả về đối tượng ghế đã được thêm
        }

        // ---------- R (Read) - Đọc/Lấy dữ liệu ghế ----------

        // Lấy tất cả ghế
        public IEnumerable<Chairs> GetAllChairs()
        {
            return _chairs;
        }

        // Lấy ghế theo ID
        public Chairs GetChairById(Guid id)
        {
            return _chairs.FirstOrDefault(c => c.id == id);
        }

        // Lấy ghế theo tên (ví dụ)
        public IEnumerable<Chairs> GetChairsByName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return Enumerable.Empty<Chairs>(); // Trả về danh sách rỗng nếu tên rỗng
            }
            // Sử dụng StringComparison.OrdinalIgnoreCase để tìm kiếm không phân biệt chữ hoa chữ thường
            return _chairs.Where(c => c.name.Contains(name, StringComparison.OrdinalIgnoreCase));
        }

        // ---------- U (Update) - Cập nhật ghế ----------
        public Chairs UpdateChair(Chairs chair)
        {
            if (chair == null)
            {
                throw new ArgumentNullException(nameof(chair));
            }

            var existingChair = _chairs.FirstOrDefault(c => c.id == chair.id);
            if (existingChair == null)
            {
                return null; // Không tìm thấy ghế để cập nhật
            }

            // Cập nhật các thuộc tính của ghế đã tồn tại
            existingChair.name = chair.name;
            existingChair.stock = chair.stock;
            existingChair.price = chair.price;
            existingChair.description = chair.description;

            return existingChair; // Trả về đối tượng ghế đã được cập nhật
        }

        // ---------- D (Delete) - Xóa ghế ----------
        public bool DeleteChair(Guid id)
        {
            var chairToRemove = _chairs.FirstOrDefault(c => c.id == id);
            if (chairToRemove == null)
            {
                return false; // Không tìm thấy ghế để xóa
            }

            _chairs.Remove(chairToRemove);
            return true; // Xóa thành công
        }
    }
}