from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar, QTableWidgetItem, QWidget


class NumberedDomainEdit(QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setObjectName("domainEditor")
        self.setLayoutDirection(Qt.LeftToRight)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.gutter = _LineNumbers(self)
        self.blockCountChanged.connect(self._resize_gutter)
        self.updateRequest.connect(self._update_gutter)
        self._resize_gutter()

    def _resize_gutter(self):
        width = self.fontMetrics().horizontalAdvance("0" * len(str(self.blockCount()))) + 18
        if self.viewportMargins().left() != width:
            self.setViewportMargins(width, 0, 0, 0)
        viewport = self.viewport().geometry()
        self.gutter.setGeometry(viewport.x() - width, viewport.y(), width, viewport.height())
        self.gutter.update()

    def _update_gutter(self, rect, delta):
        if delta:
            self.gutter.scroll(0, delta)
        else:
            self.gutter.update(0, rect.y(), self.gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._resize_gutter()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_gutter()


class _LineNumbers(QWidget):
    def paintEvent(self, event):
        editor = self.parentWidget()
        painter = QPainter(self)
        painter.fillRect(event.rect(), QColor("#081725"))
        painter.setPen(QColor("#1e4057"))
        painter.drawLine(self.width() - 1, 0, self.width() - 1, self.height())
        painter.setFont(editor.font())
        painter.setPen(QColor("#7498ad"))
        block = editor.firstVisibleBlock()
        while block.isValid():
            top = round(editor.blockBoundingGeometry(block).translated(editor.contentOffset()).top())
            if top > event.rect().bottom():
                break
            height = round(editor.blockBoundingRect(block).height())
            if block.isVisible() and top + height >= event.rect().top():
                painter.drawText(0, top, self.width() - 6, height, Qt.AlignRight | Qt.AlignVCenter,
                                 str(block.blockNumber() + 1))
            block = block.next()


class MetricSortItem(QTableWidgetItem):
    def __init__(self, value, tooltip):
        super().__init__()
        self.setData(Qt.UserRole, value)
        self.setData(Qt.AccessibleTextRole, tooltip)
        self.setToolTip(tooltip)

    def __lt__(self, other):
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


def result_metric(text, tone="", *, stability=None):
    label = QLabel(text)
    label.setObjectName("labMetric")
    label.setProperty("tone", tone)
    label.setLayoutDirection(Qt.LeftToRight)
    label.setAlignment(Qt.AlignCenter)
    label.setAttribute(Qt.WA_TransparentForMouseEvents)
    if stability is None:
        return label
    holder = QWidget()
    holder.setLayoutDirection(Qt.LeftToRight)
    holder.setAttribute(Qt.WA_TransparentForMouseEvents)
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(2, 0, 2, 0)
    layout.setSpacing(5)
    layout.setAlignment(Qt.AlignCenter)
    bar = QProgressBar()
    bar.setObjectName("labStability")
    bar.setProperty("tone", tone)
    bar.setTextVisible(False)
    bar.setFixedSize(30, 5)
    bar.setRange(0, 100)
    bar.setValue(stability)
    layout.addWidget(label)
    layout.addWidget(bar)
    return holder
