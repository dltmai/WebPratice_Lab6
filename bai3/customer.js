const amqp = require("amqplib");
const mongoose = require("mongoose");

// Cấu hình các URL
const RABBITMQ_URL = "amqp://localhost";
const QUEUE = "messages";
const MONGO_URI = "mongodb://localhost:27017/rabbitmq_example";

// Kết nối MongoDB
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Định nghĩa Schema và Model
const messageSchema = new mongoose.Schema({
  id: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  content: { type: String, required: true },
  metadata: { type: Object, required: false },
  timestamp: { type: Date, required: true },
});
const Message = mongoose.model("Message", messageSchema);

// Hàm tiêu thụ tin nhắn từ RabbitMQ
async function consumeMessages() {
  const connection = await amqp.connect(RABBITMQ_URL);
  const channel = await connection.createChannel();
  await channel.assertQueue(QUEUE);

  console.log(`Waiting for messages in ${QUEUE}...`);

  channel.consume(QUEUE, async (msg) => {
    if (msg !== null) {
      const messageContent = JSON.parse(msg.content.toString());
      console.log("Message received:", messageContent);

      try {
        // Lưu tin nhắn vào MongoDB
        const savedMessage = await Message.create({
          ...messageContent,
          metadata: { source: "RabbitMQ", priority: "High" },
        });
        console.log("Message saved to MongoDB:", savedMessage);
      } catch (err) {
        console.error("Error saving message to MongoDB:", err);
      }

      // Xác nhận tin nhắn đã xử lý
      channel.ack(msg);
    }
  });
}

// Gọi hàm tiêu thụ tin nhắn
consumeMessages().catch(console.error);
